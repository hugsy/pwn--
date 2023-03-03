#include <argparse.hpp>
#include <filesystem>
#include <pwn.hpp>
#include <ranges>

int
ListServices()
{
    auto res = pwn::win::Service::List();
    if ( Failed(res) )
    {
        return -1;
    }

    auto IsServiceRunningDriver = [](pwn::win::ServiceInfo const& s)
    {
        return s.Status == SERVICE_RUNNING && s.Type == SERVICE_KERNEL_DRIVER;
    };

    for ( auto const& SvcInfo : Value(res) | std::views::filter(IsServiceRunningDriver) )
    {
        if ( SvcInfo.Path.has_value() )
            info(L"Name='{}' Path='{:s}'", SvcInfo.Name.c_str(), SvcInfo.Path.value().c_str());
    }

    return 0;
}

int
AddService(std::string_view const& name, std::filesystem::path const& binPath)
{
    if ( !std::filesystem::exists(binPath) )
    {
        return -1;
    }

    std::wstring wsName    = pwn::utils::StringLib::To<std::wstring>(name);
    std::wstring wsBinPath = pwn::utils::StringLib::To<std::wstring>(std::filesystem::absolute(binPath).string());

    if ( Failed(pwn::win::Service::Create(wsName, wsBinPath, pwn::win::ServiceType::KernelDriver)) )
    {
        return -1;
    }

    return Success(pwn::win::Service::Start(wsName)) ? 0 : -1;
}


int
DelService(std::string_view const& name)
{
    std::wstring wsName = pwn::utils::StringLib::To<std::wstring>(name);
    bool res            = Success(pwn::win::Service::Stop(wsName)) && Success(pwn::win::Service::Destroy(wsName));
    return res ? 0 : -1;
}


auto
main(const int argc, const char** argv) -> int
{
    //
    // Argument parsing
    //
    argparse::ArgumentParser program("LoadDriver");

    program.add_argument("--debug").default_value(false).implicit_value(true);

    argparse::ArgumentParser list_command("list");
    list_command.add_description("List all running drivers");
    program.add_subparser(list_command);

    argparse::ArgumentParser add_command("add");
    add_command.add_description("Load a driver");
    add_command.add_argument("name").help("Service name");
    add_command.add_argument("file").help("Driver path to load");
    program.add_subparser(add_command);

    argparse::ArgumentParser del_command("del");
    del_command.add_description("Unload a driver");
    del_command.add_argument("name").help("Service name");
    program.add_subparser(del_command);

    try
    {
        program.parse_args(argc, argv);
    }
    catch ( const std::runtime_error& err )
    {
        err("{}", err.what());
        return EXIT_FAILURE;
    }

    if ( program["--debug"] == true )
    {
        pwn::Context.set(pwn::log::LogLevel::Debug);
    }
    else
    {
        pwn::Context.set(pwn::log::LogLevel::Info);
    }

    //
    // Execute the subcommand
    //
    if ( program.is_subcommand_used("list") )
    {
        return ListServices();
    }

    int res = 0;

    if ( program.is_subcommand_used("add") )
    {
        auto const& options     = program.at<argparse::ArgumentParser>("add");
        auto const& serviceName = options.get<std::string>("name");
        auto const servicePath  = std::filesystem::path(options.get<std::string>("file"));
        res                     = AddService(serviceName, servicePath);
        dbg("AddService() returned {}", res);
    }

    if ( program.is_subcommand_used("del") )
    {
        auto const& options     = program.at<argparse::ArgumentParser>("del");
        auto const& serviceName = options.get<std::string>("name");
        res                     = DelService(serviceName);
        dbg("DelService() returned {}", res);
    }

    return res;
}
