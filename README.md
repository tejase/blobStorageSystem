<div id="top"></div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/tejase/blobStorageSystem">
    <img src="description/murmuringMountain.jpg" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Murmuring Mountain</h3>

  <p align="center">
    ( Backend Repository )
    <br />
    <a href="https://murmuring-mountain-24156.herokuapp.com/docs#"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://murmuring-mountain-37015.herokuapp.com/">View Demo</a>
    ·
    <a href="https://github.com/tejase/blobStorageSystem-Frontend">Frontend Repository</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

The murmuring mountain is a cool Blob File storage system. 🚀

<p align="right">(<a href="#top">back to top</a>)</p>

### Built With

- [Fast Api](https://fastapi.tiangolo.com/)
- [Mongo DB](https://www.mongodb.com/)
- [React.js](https://reactjs.org/)

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- python 3.6 +
- PIP

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/tejase/blobStorageSystem.git
   ```
2. Create a virtual environment

3. Install fastapi and other required dependancies from requirements.txt file
   ```sh
   pip3 install -r requirements.txt
   ```
4. Create a .env file in the project root with the content listed below
   ```sh
   secret = <Replace with your secret>
   algorithm = HS256
   mongoDbUri = <Replace with mongoDB URI>
   ```
5. Run the application 
   ```sh
   uvicorn index:app --reload
   ```

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->

## Usage

The murmuring mountain is a cool Blob File storage system. 🚀

Users after registering, would be able to upload and save any type of file. The murmuring mountain stores the files as small chunks efficiently, thus allowing the user to save even large files. The user can view his/her files any time in his dashboard. The user is also provided options to download, edit and delete the files he saved. The murmuring mountain also provides functionality to share the file with other users. The shared file access can be easily managed and monitored with the role based sharing provided.  

_For detailed information about functionalities, sharing and permission levels, please refer to the [Documentation](https://murmuring-mountain-24156.herokuapp.com/redoc)_

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- ROADMAP -->

## Roadmap

- [ ] User authentication
    - [ ] Session management
- [ ] Implementation of the blob storage server
    - [ ] Upload any type and size of file
    - [ ] Download Files
    - [ ] Rename uploaded files
    - [ ] Delete uploaded files
- [ ] Web-based application - Frontend
- [ ] User based access control on files
    - [ ] Sharing of files
    - [ ] Assigning roles to manage shared files
    - [ ] Revoke roles and access from shared files
- [ ] Deploy the application
    - [ ] Deployed backend server in heroku
    - [ ] Integrated with MongoDB online cluster
    - [ ] Deplyed the frontend application in heroku


<p align="right">(<a href="#top">back to top</a>)</p>
