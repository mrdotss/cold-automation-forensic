# CAF (Cold Automation Forensic)

## Overview

A web application (Django 5) designed for wired/wireless (remote) acquisition of data from Android devices, based on [WebADB](https://github.com/mrdotss/webadb), which I recently used, but with slightly more powerful features.

## Getting Started

To begin using RAAS, follow these steps to set up your development environment:

Note: 
* I don't provide feature to root the device, so you need to root the device if you want to use the physical acquisition (but some basic task doesn't need root)
* Maybe some phone will not work with other features, because need some adjustment for the device
* I can say this forensically sound tool and still in the development stage for stable use

### Prerequisites

Also documented [here](https://s3.wasabisys.com/c343765-a/User-Manual/RAAS%20-%20User%20Manual%20v1.0.pdf) with  how to use. Ensure the following dependencies are installed on your system:

- **Python 3.10+**
- **SDK Platform Tools** (Add to your PATH)
- **pip** (Python package installer)
- **node.js** (Install [node.js](https://nodejs.org/en/download/) first if you don't have it in your machine, min version 18.0 for this package)
- **yarn** (Install [yarn](https://classic.yarnpkg.com/lang/en/docs/install/#windows-stable) first if you don't have it in your machine) for installing the frontend dependencies
- **Redis server** (You can install it on the same server)
- **Virtualenv** (Optional but recommended for creating isolated Python environments)

### For The Device
- You need to enable USB Debugging on your device and connect it to your computer via USB/IP Address
- And then you can check if the device is connected by running `adb devices` on your terminal
   ```shell
   adb devices
   ```


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
    cd cold-automation-forensic\
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    celery -A core worker -l info
    ```

10. **Access the Application**:
    Open your web browser and navigate to `http://127.0.0.1:8000/` to access the RAAS application. Use the superuser account to access the admin interface at `http://127.0.0.1:8000/admin/`.

## Future Enhancements

I understand that this application is still less than perfect and that there are many aspects that need improvement. I will continue to work on developing it as effectively and efficiently as possible.

Stay tuned for more features that will be released next year. These features will enhance the capabilities of RAAS, providing more powerful tools for data acquisition and analysis.


## Todo List
- [x] Physical Acquisition (USB & Wireless)
- [ ] Logical Acquisition (40%)
- [ ] Full File System Acquisition
- [ ] Reporting System
- [ ] Improvement for Log Management
- [ ] Improvement for Case Management and Evidence Management
- [ ] Enhancement for Security (Endless)
 
## License

This project use Stisla (Dashboard Template), and Stisla is under the [MIT License](https://github.com/stisla/stisla/blob/master/LICENSE).