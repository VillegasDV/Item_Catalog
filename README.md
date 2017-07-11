# Item Catalog Project

The Item Catalog project consists of developing an application that provides a list of items within a variety of categories, as well as provide a user registration and authentication system. 

## Files
* database_setup.py - Python program which creates 'catalog.db' file
* catalog.db - Main database that is created by database_setup.py
* application.py - Main python program which executes the queries and returns the results
* /static - Contains static html files needed for the website (e.g. styles.css)
* /templates - Contains all the html template files


## How to Run
### You will need:

* Python
* Vagrant
* VirtualBox

### Setup
* Install Vagrant And VirtualBox
* Clone this repository and copy under main vagrant folder
* Launch Vagrant VM by running 'vagrant up'
* Log in using 'vagrant ssh'
* Run 'python database_setup.py' from the command line to create the database

### To Run
Run 'python application.py' from the command line to start web server
Visit http://localhost:5000/ on your browser

## License
----

David Villegas