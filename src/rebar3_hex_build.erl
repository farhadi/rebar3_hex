%% @doc Builds a new local version of your package.
%% 
%% The package .tar file is created in the current directory, but is not pushed to the repository.
%% An app named foo at version 1.2.3 will be built as foo-1.2.3.tar.
%% @end
-module(rebar3_hex_build).

-export([ init/1
        , do/1
        , format_error/1
        ]).

-include("rebar3_hex.hrl").

-define(PROVIDER, build).
-define(DEPS, [{default, lock}]).

-define(DEFAULT_FILES, ["src", "c_src", "include", "rebar.config.script"
                       ,"priv", "rebar.config", "rebar.lock"
                       ,"CHANGELOG*", "changelog*"
                       ,"README*", "readme*"
                       ,"LICENSE*", "license*"
                       ,"NOTICE"]).

%% ===================================================================
%% Public API
%% ===================================================================
-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([{name, ?PROVIDER},
                                 {module, ?MODULE},
                                 {namespace, hex},
                                 {bare, true},
                                 {deps, ?DEPS},
                                 {example, "rebar3 hex build"},
                                 {short_desc, "Build a new local version of your package"},
                                 {desc, ""},
                                 {opts, [{app, $a, "app", {string, undefined}, help(app)}]}]),
    State1 = rebar_state:add_provider(State, Provider),
    {ok, State1}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, term()}.
do(State) ->
    case rebar3_hex:task_state(State) of
        {ok, Task} ->
            handle_task(Task);
        {error, Reason} ->
            ?RAISE(Reason)
    end.

-spec format_error(any()) -> iolist().
format_error(ErrList) when is_list(ErrList) ->
  F = fun(Err, Acc) ->
          ErrStr = format_error(Err),
          Acc ++ "     " ++ ErrStr ++ "\n"
      end,
  lists:foldl(F, "Validator Errors:\n", ErrList);
format_error({validation_errors, Errs}) ->
    lists:map(fun(E) -> format_error(E) end, Errs);
format_error({has_contributors, AppName}) ->
    Err = "~ts.app.src : deprecated field contributors found",
    io_lib:format(Err, [AppName]);
format_error({has_maintainers, AppName}) ->
    Err = "~ts.app.src : deprecated field maintainers found",
    io_lib:format(Err, [AppName]);
format_error({no_description, AppName}) ->
    Err = "~ts.app.src : missing or empty description property",
    io_lib:format(Err, [AppName]);
format_error({no_license, AppName}) ->
    Err = "~ts.app.src : missing or empty licenses property",
    io_lib:format(Err, [AppName]);
format_error({invalid_semver, {AppName, Version}}) ->
    Err = "~ts.app.src : non-semantic version number \"~ts\" found",
    io_lib:format(Err, [AppName, Version]);
format_error({has_unstable_deps, Deps}) ->
    MainMsg = "The following pre-release dependencies were found : ",
    DepList = [io_lib:format("~s - ~s ", [Pkg, Ver]) || {Pkg, Ver} <- Deps],
    Msg = [
        "In the future packages with pre-release dependencies will be considered unstable ",
        "and will be prevented from being published. ",
        "We recommend you upgrade your these dependencies as soon as possible"
    ],
    io_lib:format("~s~n~n~s~n~n~s~n", [MainMsg, DepList, Msg]);

format_error({app_not_found, AppName}) ->
     io_lib:format("App ~s specified with --app switch not found in project", [AppName]);
format_error({non_hex_deps, Excluded}) ->
    Err = "Can not build package because the following deps are not available"
         ++ " in hex: ~s",
    io_lib:format(Err, [string:join(Excluded, ", ")]);
format_error(Reason) ->
    rebar3_hex_error:format_error(Reason).

%% ===================================================================
%% Private
%% ===================================================================

handle_task(#{args := #{app := undefined}, state := State, apps := Apps}) ->
    Selected = rebar3_hex_io:select_apps(Apps),
    lists:foreach(fun(App) -> build(State, App) end, Selected),
    {ok, State};

handle_task(#{apps := [App], state := State}) ->
    rebar_api:error("--app switch has no effect in single app projects", []),
    build(State, App);

handle_task(#{args := #{app := AppName}, apps := Apps} = Task) ->
    case rebar3_hex_app:find(Apps, AppName) of
        {error, app_not_found} ->
            ?RAISE({app_not_found, AppName});
        {ok, App} ->
            #{state := State} = Task,
            build(State, App)
    end.

build(State, App) ->
    assert_valid_app(State, App),
    Package = #{name := Name, version := Version} = build_package(State, App),
    print_package_info(Package),
    Tarball = create_tarball(Package),
    FileName = binary_to_list(Name)  ++ "-" ++ Version ++ ".tar",
    case file:write_file(FileName, Tarball) of
        ok ->
            rebar_api:info("Saved to ~s", [FileName]),
            {ok, State};
        Error ->
            ?RAISE({build, Error})
    end.

build_package(State, App) ->
    Name = rebar_app_info:name(App),

    Version = rebar3_hex_app:vcs_vsn(State, App),

    %% Note we should not implicitly do this IMO
    {application, _, AppDetails} = rebar3_hex_file:update_app_src(App, Version),

    Deps = rebar_state:get(State, {locks, default}, []),
    TopLevel = gather_deps(Deps),
    AppDir = rebar_app_info:dir(App),
    Config = rebar_config:consult(AppDir),
    ConfigDeps = proplists:get_value(deps, Config, []),
    Deps1 = update_versions(ConfigDeps, TopLevel),
    Description = proplists:get_value(description, AppDetails, ""),
    PackageFiles = include_files(Name, AppDir, AppDetails),
    Licenses = proplists:get_value(licenses, AppDetails, []),
    Links = proplists:get_value(links, AppDetails, []),
    BuildTools = proplists:get_value(build_tools, AppDetails, [<<"rebar3">>]),

    %% We check the app file for the 'pkg' key which allows us to select
    %% a package name other then the app name, if it is not set we default
    %% back to the app name.
    PkgName = rebar_utils:to_binary(proplists:get_value(pkg_name, AppDetails, Name)),

    Optional = [{<<"app">>, Name},
                {<<"parameters">>, []},
                {<<"description">>, rebar_utils:to_binary(Description)},
                {<<"files">>, [binarify(File) || {File, _} <- PackageFiles]},
                {<<"licenses">>, binarify(Licenses)},
                {<<"links">>, to_map(binarify(Links))},
                {<<"build_tools">>, binarify(BuildTools)}],
    OptionalFiltered = [{Key, Value} || {Key, Value} <- Optional, Value =/= []],
    Metadata = maps:from_list([{<<"name">>, PkgName}, {<<"version">>, binarify(Version)},
                               {<<"requirements">>, maps:from_list(Deps1)} | OptionalFiltered]),
    #{name => PkgName,
      deps => Deps1,
      version => Version,
      metadata => Metadata,
      files => PackageFiles}.

print_package_info(Package) ->
    #{metadata := Meta, files := Files, deps := Deps, name := Name, version := Version} = Package,
    rebar3_hex_io:say("Building ~ts ~ts", [Name, Version]),
    rebar3_hex_io:say("  Description: ~ts", [rebar_utils:to_list(maps:get(<<"description">>, Meta, ""))]),
    rebar3_hex_io:say("  Dependencies:~n    ~ts", [format_deps(Deps)]),
    rebar3_hex_io:say("  Included files:~n    ~ts", [string:join([F || {F, _} <- Files], "\n    ")]),
    rebar3_hex_io:say("  Licenses: ~ts", [format_licenses(maps:get(<<"licenses">>, Meta, []))]),
    rebar3_hex_io:say("  Links:~n    ~ts", [format_links(maps:get(<<"links">>, Meta, []))]),
    rebar3_hex_io:say("  Build tools: ~ts", [format_build_tools(maps:get(<<"build_tools">>, Meta))]).

create_tarball(#{metadata := Meta, files := Files}) ->
    case hex_tarball:create(Meta, Files) of
        {ok, #{tarball := Tarball, inner_checksum := _Checksum}} ->
            Tarball;
        Error ->
            ?RAISE(Error)
    end.

assert_valid_app(State, App) ->
    Name = rebar_app_info:name(App),
    Version = rebar_app_info:original_vsn(App),
    ResolvedVersion = rebar_utils:vcs_vsn(App, Version, State),
    {application, _, AppDetails} = rebar3_hex_file:update_app_src(App, ResolvedVersion),
    Deps = rebar_state:get(State, {locks, default}, []),
    AppData = #{name => Name, version => ResolvedVersion, details => AppDetails, deps => Deps},
    case rebar3_hex_app:validate(AppData) of
        ok ->
            {ok, State};
       {error, #{warnings := Warnings, errors := Errors}} -> 
            lists:foreach(fun(W) -> rebar_log:log(warn, format_error(W), []) end, Warnings),
            case Errors of 
                [] -> 
                    {ok, State};
                Errs -> 
                    ?RAISE({validation_errors, Errs})
            end
    end.

gather_deps(Deps) ->
    case rebar3_hex_app:get_deps(Deps) of
        {ok, Top} ->
            Top;
        {error, Reason} ->
             ?RAISE(Reason)
    end.

known_exclude_file(Path, ExcludeRe) ->
    KnownExcludes = [
                     "~$",        %% emacs temp files
                     "\\.o$",     %% c object files
                     "\\.so$",    %% compiled nif libraries
                     "\\.swp$"    %% vim swap files
                    ],
    lists:foldl(fun(_, true) -> true;
                   (RE, false) ->
                        re:run(Path, RE) =/= nomatch
                end, false, KnownExcludes ++ ExcludeRe).

exclude_file(Path, ExcludeFiles, ExcludeRe) ->
    lists:keymember(Path, 2, ExcludeFiles) orelse
        known_exclude_file(Path, ExcludeRe).

%% allows us to support lists of tuples or maps for metadata the user writes in .app.src
to_map(Map) when is_map(Map) ->
    Map;
to_map(List) when is_list(List) ->
    maps:from_list(List).

include_files(Name, AppDir, AppDetails) ->
    _ = maybe_print_checkouts_warnings(AppDir),

    AppSrc = {application, to_atom(Name), AppDetails},
    FilePaths = proplists:get_value(files, AppDetails, ?DEFAULT_FILES),
    IncludeFilePaths = proplists:get_value(include_files, AppDetails, []),
    ExcludeFilePaths = proplists:get_value(exclude_files, AppDetails, []),
    ExcludeRes = proplists:get_value(exclude_regexps, AppDetails, []),

    AllFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(FilePaths, AppDir)),
    IncludeFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(IncludeFilePaths, AppDir)),
    ExcludeFiles = lists:ukeysort(2, rebar3_hex_file:expand_paths(ExcludeFilePaths, AppDir)),

    %% We filter first and then include, that way glob excludes can be
    %% overwritten be explict includes
    FilterExcluded = lists:filter(fun ({_, Path}) ->
                                      not exclude_file(Path, ExcludeFiles, ExcludeRes)
                                  end, AllFiles),
    WithIncludes = lists:ukeymerge(2, FilterExcluded, IncludeFiles),

    AppFileSrc = filename:join("src", rebar_utils:to_list(Name)++".app.src"),
    AppSrcBinary = rebar_utils:to_binary(lists:flatten(io_lib:format("~tp.\n", [AppSrc]))),
    lists:keystore(AppFileSrc, 1, WithIncludes, {AppFileSrc, AppSrcBinary}).

maybe_print_checkouts_warnings(AppDir) ->
    {HasCheckouts, Checkouts} = has_checkouts_for(AppDir),
    HasCheckouts andalso
        rebar_log:log(warn, "~p directory found; this might interfere with building", [Checkouts]).

has_checkouts_for(AppDir) ->
    Checkouts = filename:join(AppDir, "_checkouts"),
    {filelib:is_dir(Checkouts), Checkouts}.

format_deps(Deps) ->
    Res = [rebar_utils:to_list(<<N/binary, " ", V/binary>>) || {N, #{<<"requirement">> := V}} <- Deps],
    string:join(Res, "\n    ").

format_licenses(Licenses) ->
    string:join([rebar_utils:to_list(L) || L <- Licenses], ", ").

format_links(Links) ->
    Links1 = maps:to_list(Links),
    LinksList = [lists:flatten([rebar_utils:to_list(Name), ": ", rebar_utils:to_list(Url)]) || {Name, Url} <- Links1],
    string:join(LinksList, "\n    ").

format_build_tools(BuildTools) ->
    string:join([io_lib:format("~s", [Tool]) || Tool <- BuildTools], ", ").

update_versions(ConfigDeps, Deps) ->
    [begin
         case lists:keyfind(binary_to_atom(N, utf8), 1, ConfigDeps) of
             {_, V} when is_binary(V) ->
                 Req =  {<<"requirement">>, V},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))};
             {_, V} when is_list(V) ->
                 Req = {<<"requirement">>, rebar_utils:to_binary(V)},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))};
             _ ->
                 %% using version from lock. prepend ~> to make it looser
                 {_, Version} = lists:keyfind(<<"requirement">>, 1, M),
                 Req = {<<"requirement">>, <<"~>", Version/binary>>},
                 {N, maps:from_list(lists:keyreplace(<<"requirement">>, 1, M, Req))}
         end
     end || {N, M} <- Deps].

binarify(Term) when is_boolean(Term) ->
    Term;
binarify(Term) when is_atom(Term) ->
    atom_to_binary(Term, utf8);
binarify([]) ->
    [];
binarify(Map) when is_map(Map) ->
    maps:from_list(binarify(maps:to_list(Map)));
binarify(Term) when is_list(Term) ->
    case io_lib:printable_unicode_list(Term) of
        true ->
            rebar_utils:to_binary(Term);
        false ->
            [binarify(X) || X <- Term]
    end;
binarify({Key, Value}) ->
    {binarify(Key), binarify(Value)};
binarify(Term) ->
    Term.

-spec to_atom(atom() | string() | binary() | integer() | float()) ->
                     atom().
to_atom(X) when erlang:is_atom(X) ->
    X;
to_atom(X) when erlang:is_list(X) ->
    list_to_existing_atom(X);
to_atom(X) ->
    to_atom(rebar_utils:to_list(X)).


help(app) ->
    "Specifies the app to use with the build command"
    "Note that the app switch and value only have to be provided if you are building within an umbrella.".
