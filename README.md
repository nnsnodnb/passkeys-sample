# passkeys-sample

## backend

Server is provided by Django project.  
This project is used 8000 port.

### Runserver

You can use docker.

```bash
cd backend
docker build -t passkeys-sample-backend .
docker run -it -d -p 8000:8000 passkeys-sample-backend
```

## client

Client is provided by iOS app.

### Environments

- Xcode 15.1

## License

This software is licensed under the MIT License (See [LICENSE](LICENSE)).
