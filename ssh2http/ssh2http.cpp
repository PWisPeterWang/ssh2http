#include <boost/asio.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <sstream>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/beast/core/detail/base64.hpp>

namespace net = boost::asio;
using net::ip::tcp;

class ssh2http
{
public:
    ssh2http(std::string target_host, std::string target_port, std::string proxy_host,
        std::string proxy_port, std::string auth)
        : io_context_()
        , resolver_(io_context_)
        , socket_(io_context_)
        , stdin_(io_context_, STDIN_FILENO)
    {

        std::ostringstream oss;
        oss << "CONNECT " << proxy_host << ":" << proxy_port << " HTTP/1.0";
        if (!auth.empty())
        {
            if (auth.size() > 4096)
            {
                throw std::runtime_error("auth info too long");
            }
            char buffer[8192];
            boost::beast::detail::base64::encode(buffer, auth.data(), auth.size());
            oss << "\nProxy-Authorization: Basic " << buffer;
        }

        oss << "\r\n\r\n";

        proxy_request_ = oss.str();

        tcp::resolver::query query(proxy_host, proxy_port);
        resolver_.async_resolve(query, [this](const boost::system::error_code &ec,
                                           tcp::resolver::iterator it) { handle_resolve(ec, it); });
    }

    void run()
    {
        io_context_.run();
    }

    ~ssh2http() {}

private:
    void handle_resolve(const boost::system::error_code &ec, tcp::resolver::iterator it)
    {
        if (!ec)
        {
            tcp::endpoint endpoint = *it;
            socket_.async_connect(
                endpoint, [this](const boost::system::error_code &ec) { handle_connect(ec); });
        }
        else
        {
            std::cerr << "resolve error: " << ec.message() << "\n";
        }
    }

    void handle_connect(const boost::system::error_code &ec)
    {
        if (!ec)
        {
            socket_.async_write_some(net::buffer(proxy_request_, proxy_request_.size()),
                [this](const boost::system::error_code &ec, size_t bytes_transferred) {
                    handle_write_request(ec);
                });
        }
        else
        {
            std::cerr << "connect error: " << ec.message() << "\n";
        }
    }
    void handle_write_request(const boost::system::error_code &ec)
    {
        if (!ec)
        {
            read_proxy();
            read_stdin();
        }
        else
        {
            std::cerr << "write request error: " << ec.message() << "\n";
        }
    }
    void read_proxy()
    {
        net::async_read_until(socket_, proxy_buffer_, "\r\n\r\n",
            [this](const boost::system::error_code &ec, size_t bytes_transferred) {
                handle_read_proxy(ec, bytes_transferred);
            });
    }
    void handle_read_proxy(const boost::system::error_code &ec, size_t bytes_transferred)
    {
        if (!ec)
        {
            std::cout.write(
                net::buffer_cast<const char *>(proxy_buffer_.data()), bytes_transferred);
            proxy_buffer_.consume(bytes_transferred);
            read_proxy();
        }
        else
        {
            std::cerr << "read proxy error: " << ec.message() << "\n";
            io_context_.stop();
        }
    }
    void read_stdin()
    {
        net::async_read_until(stdin_, stdin_buffer_, "\n",
            [this](const boost::system::error_code &ec, size_t bytes_transferred) {
                handle_read_stdin(ec, bytes_transferred);
            });
    }
    void handle_read_stdin(const boost::system::error_code &ec, size_t bytes_transferred)
    {
        if (!ec)
        {
            net::async_write(socket_,
                net::buffer(
                    net::buffer_cast<const char *>(stdin_buffer_.data()), bytes_transferred),
                [this](const boost::system::error_code &ec, size_t bytes_transferred) {
                    handle_write_to_proxy(ec, bytes_transferred);
                });
        }
        else
        {
            std::cerr << "read stdin error: " << ec.message() << "\n";
            io_context_.stop();
        }
    }

    void handle_write_to_proxy(const boost::system::error_code &ec, size_t bytes_transferred)
    {
        if (!ec)
        {
            stdin_buffer_.consume(bytes_transferred);
            read_stdin();
        }
        else
        {
            std::cerr << "write to proxy error: " << ec.message() << "\n";
            io_context_.stop();
        }
    }

private:
    net::io_context io_context_;
    tcp::resolver resolver_;
    tcp::socket socket_;
    net::posix::stream_descriptor stdin_;
    std::string proxy_request_;
    net::streambuf proxy_buffer_;
    net::streambuf stdin_buffer_;
};

namespace po = boost::program_options;

int main(int argc, char const *argv[])
{
    po::options_description desc("ssh2http is a simple tool to convert ssh connection to http "
                                 "proxy connection.\nUsage: ssh2http [options] <target_host> "
                                 "<target_port> <proxy_host> <proxy_port>\nOptions");

    // clang-format off
    desc.add_options()
        ("help,h", "print help message")
        ("version,v", "print version")
        ("target_host", po::value<std::string>()->required() , "target host")
        ("target_port", po::value<std::string>()->required(), "target port")
        ("proxy_host", po::value<std::string>()->required(), "proxy host")
        ("proxy_port", po::value<std::string>()->required(), "proxy port")
        ("auth", po::value<std::string>(), "auth info, format: username:password");
    // clang-format on

    po::positional_options_description p;
    p.add("target_host", 1);
    p.add("target_port", 1);
    p.add("proxy_host", 1);
    p.add("proxy_port", 1);
    p.add("auth", 1);

    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        if (vm.count("help"))
        {
            std::cout << desc << "\n";
            return 0;
        }
        if (vm.count("version"))
        {
            std::cout << "ssh2http version 0.1\n";
            return 0;
        }
        po::notify(vm);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        std::cout << desc << "\n";
        return 1;
    }

    std::string target_host = vm["target_host"].as<std::string>();
    std::string target_port = vm["target_port"].as<std::string>();
    std::string proxy_host = vm["proxy_host"].as<std::string>();
    std::string proxy_port = vm["proxy_port"].as<std::string>();
    std::string auth = vm.count("auth") ? vm["auth"].as<std::string>() : "";

    try
    {
        ssh2http s(target_host, target_port, proxy_host, proxy_port, auth);
        s.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
