
## Description
SecureScan is a powerful, lightweight web application designed for Linux-based systems to help security analysts, developers, and ethical hackers quickly identify common vulnerabilities and perform reconnaissance on target websites.

<b>Note:</b> It will only work in the linux based distribution.

## Environment Variables
To run this project, you will need to add the following environment variables to your .env file

#### For Frontend:
`VITE_BACKEND_URL`: Your backend url

`VITE_SOCKET_URL`: URL of Socket running using `socket_runner.py` file 

#### For Backend:
`FRONTEND_URL`: Your frontend URL
 
`GEMINI_API_KEY`: Gemini API Key

## Deployment

#### For Frontend:

To Install all this modules run
```bash
  npm install
```

To run the frontend
```bash
  npm run dev
```

#### For Backend:

To Install all the Dependencies run
```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirement.txt 
```

To run the Backend
```bash
  source .venv/bin/activate
  python3 app.py
```
and
```bash
  source .venv/bin/activate
  python3 socket_runner.py
```

### Note:
- it is only made for educational purpose, make sure whichever website you scan you have a authorized permission.
- you may get CORS problem while running the application, you can modify the `app.py` and `socket_runner.py` file as per your need.

## Features

- URL Based Scanning
- Reconnaissance Tools
- Vulnerability Tools
- Gemini bot summary
- User Friendly Interface
- Linux Based Backend

## Credits
- [Sameer singh bhandari](https://github.com/xtrimDev/)
- [Anas Ali](https://github.com/xtrimDev/)
