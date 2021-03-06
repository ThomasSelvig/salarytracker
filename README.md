# salarytracker
 Intuitive and secure system for tracking hours worked across multiple accounts

### Features (Node JS)
* JWT authentication
* PUG html rendering engine + Bootstrap CSS
* Sqlite3 database
* Credentials are stored as salted hashes
* Logging using Morgan

# Demo
#### (all pages except /login require authentication, will redirect you to /login if no authentication is provided)

### Login / Register page
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/loginpage.png)

### Login / Register requirements
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/loginpage_requirements.png)


### Main UI
#### Logged entries are stored independently per user (a user can only see their own logs)
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/index.png)

### Date / time selection UI
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/selection_ui.png)

### View logged hours' UI
#### Uses different hourly pay depending on whether or not it's weekend
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/view_logged.png)

### Mobile friendly
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/mobile.png)

### Users' login credentials are stored securely using salted hashes
![](https://raw.githubusercontent.com/ThomasSelvig/salarytracker/main/demo/salted_hashes.png)
