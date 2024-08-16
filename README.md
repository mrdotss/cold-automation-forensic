# CAF (Cold Automation Forensic)

## Overview

 **CAF (Cold Automation Forensic)**, a web application designed to streamline the remote acquisition of data from Android devices.

## Key Features

CAF provides an array of powerful features to enhance the digital forensic investigation process:

- **Remote Data Acquisition**: Efficiently collect digital evidence from Android devices remotely. *(Note: Currently supports only physical acquisition)*.
- **Secure Data Handling**: Ensure safe and secure data acquisition processes to maintain the integrity of digital evidence.
- **Evidence Information Retrieval**: Retrieve comprehensive information about acquired evidence, including metadata and timestamps.
- **Advanced Forensic Tools**: Utilize built-in tools to capture screenshots, access terminal commands, and log app activities directly from your browser.
- **Evidence and Case Management**: Efficiently manage and organize evidence and cases, ensuring streamlined forensic investigations.
- **Intuitive UI/UX**: Experience a user-friendly interface designed for ease of use (Currently use Stisla 3 Admin Template).

## Getting Started

To begin using RAAS, follow these steps to set up your development environment:

### Prerequisites

Ensure the following dependencies are installed on your system:

- **Python 3.10+**
- **SDK Platform Tools** (Add to your PATH)
- **pip** (Python package installer)
- **node.js** (Install [node.js](https://nodejs.org/en/download/) first if you don't have it in your machine, min version 18.0 for this package)
- **yarn** (Install [yarn](https://classic.yarnpkg.com/lang/en/docs/install/#windows-stable) first if you don't have it in your machine)
- **Redis server** (You can install it on the same server)
- **Virtualenv** (Optional but recommended for creating isolated Python environments)

### Step-by-Step Setup Guide

1. **Clone the Repository or Extract the Source Code**:
    ```sh
    git clone [repository_url]    # or extract the folder
    cd cold-forensic-automation\
    ```
2. **Install yarn packages for the frontend**:
    ```sh
    cd apps\    # Go to the apps directory
    yarn install
    ```
3. **Create and Activate a Virtual Environment**:
    ```sh
    cd ..   # Go back to the root directory
    python3 -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

4. **Install Dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

5. **Install Django and Set Up the Database**:
    ```sh
    python manage.py migrate
    ```

6. **Create a Superuser (Optional)**:
    ```sh
    python manage.py createsuperuser
    ```

7. **Collect Static Files**:
    ```sh
    python manage.py collectstatic
    ```

8. **Run the Server**:
    ```sh
    daphne core.asgi:application
    ```

9. **Run the Worker (New Terminal)**:
    ```sh
    cd raas
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    celery -A core worker -l info
    ```

10. **Access the Application**:
    Open your web browser and navigate to `http://127.0.0.1:8000/` to access the RAAS application. Use the superuser account to access the admin interface at `http://127.0.0.1:8000/admin/`.

## Future Enhancements

Stay tuned for more features that will be released next year. These features will enhance the capabilities of RAAS, providing more powerful tools for data acquisition and analysis.


## License

This project use Stisla, and Stisla is under the [MIT License](https://github.com/stisla/stisla/blob/master/LICENSE).