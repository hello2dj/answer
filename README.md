# 1. 增加鉴权
# 2. 整体增加了 /answer 的前缀, 必须走代理才能访问

<a href="https://answer.dev">
    <img alt="logo" src="docs/img/logo.svg" height="99px">
</a>

# Answer - Build Q&A community

An open-source knowledge-based community software. You can use it to quickly build your Q&A community for product technical support, customer support, user communication, and more.

To learn more about the project, visit [answer.dev](https://answer.dev).

[![LICENSE](https://img.shields.io/github/license/answerdev/answer)](https://github.com/answerdev/answer/blob/main/LICENSE)
[![Language](https://img.shields.io/badge/language-go-blue.svg)](https://golang.org/)
[![Language](https://img.shields.io/badge/language-react-blue.svg)](https://reactjs.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/answerdev/answer)](https://goreportcard.com/report/github.com/answerdev/answer)
[![Discord](https://img.shields.io/badge/discord-chat-5865f2?logo=discord&logoColor=f5f5f5)](https://discord.gg/Jm7Y4cbUej)

## Screenshots

![screenshot](docs/img/screenshot.png)

## Quick start

### Running with docker

```bash
docker run -d -p 9080:80 -v answer-data:/data --name answer answerdev/answer:latest
```

For more information, see [Installation](https://answer.dev/docs/installation)

## Contributing

Contributions are always welcome!

See [CONTRIBUTING](https://answer.dev/docs/development/contributing/) for ways to get started.

## License

[Apache License 2.0](https://github.com/answerdev/answer/blob/main/LICENSE)
