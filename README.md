# JWT Maps Go Server

This is a Dockerized Go server with JWT-based authentication. Follow the instructions below to build, run, and interact with the server.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started) installed.

### Build the Docker Image

```bash
docker build -t jwt-maps-go-server .
```

Run the Docker Container

```bash
docker run -p 8080:8080 my-go-server
```
The server will now be accessible at http://localhost:8080.

Here is the formatted Markdown file:

# API Endpoints

## 1. Login (POST `/login`)
**Description**: Authenticate and retrieve `access_token` and `refresh_token`.

**Request**:
* **URL**: `http://localhost:8080/login`
* **Headers**: `Content-Type: application/json`
* **Body**:

```json
{
  "username": "user",
  "password": "password"
}
```

**Response**:
* **200 OK**:

```json
{
  "access_token": "<access_token>",
  "refresh_token": "<refresh_token>"
}
```
* **401 Unauthorized** for invalid credentials.

## 2. Refresh Token (POST `/refresh`)
**Description**: Use `refresh_token` to obtain a new `access_token`.

**Request**:
* **URL**: `http://localhost:8080/refresh`
* **Headers**: `Content-Type: application/json`
* **Body**:

```json
{
  "refresh_token": "<refresh_token>"
}
```

**Response**:
* **200 OK**:

```json
{
  "access_token": "<new_access_token>",
  "refresh_token": "<new_refresh_token>"
}
```
* **401 Unauthorized** if the refresh token is invalid.

## 3. Get Locations (GET `/locations`)
**Description**: Access protected endpoint to retrieve location data. Requires a valid `access_token`.

**Request**:
* **URL**: `http://localhost:8080/locations`
* **Headers**:
   * `Authorization: Bearer <access_token>`

**Response**:
* **200 OK**:

```json
[
  {
    "latitude": 37.9766618,
    "longitude": -122.8476458,
    "formattedAddress": "1111 California St, San Francisco, CA"
  },
  {
    "placeID": "ChIJf17NcIyAhYARmPyoC3oxN-4"
  },
  ...
]
```
* **401 Unauthorized** if the token is missing or invalid.