from flask import Flask, request, Response, send_from_directory
import subprocess
import os
import sys

app = Flask(__name__)


@app.route('/')
def home():
    # Redirect to the Streamlit app
    process = subprocess.Popen(
        [
            "streamlit", "run", "../app.py",
            "--server.port=8501",
            "--server.headless=true",
            "--browser.serverAddress=localhost",
            "--browser.gatherUsageStats=false",
            "--server.enableCORS=false",
            "--server.enableXsrfProtection=false"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Return a message explaining how to access the app
    return """
    <html>
    <head>
        <title>DNS Analyzer</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background-color: #f9f9f9; padding: 20px; border-radius: 5px; }
            h1 { color: #333; }
            a { color: #0066cc; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>DNS Analyzer</h1>
            <p>Vercel doesn't support Streamlit applications directly.</p>
            <p>Please visit your app at your Streamlit Cloud deployment: 
               <a href="https://your-app-name.streamlit.app">https://your-app-name.streamlit.app</a></p>
        </div>
    </body>
    </html>
    """


# Need this for Vercel
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
