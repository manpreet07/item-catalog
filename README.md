# Item-Catalog

Catalog Item App is integrated with third party user registration and authentication that provides a list of items within a variety of categories. You can CUD Categories and CUD Items to your categories

In order to run this application, please follow following steps

1. Go to directory /vagrant
2. Run command "vagrant up" and than once vagrant is up run "vagrant ssh"
3. Go to /vagrant/itemCatalog
4. Run python database_setup.py that will create necessary database tables
5. Once database created successfully, you can run item.py to populate database.
6. Run python project.py
7. Web App will run on http://localhost:5000
8. Go to browser on type http://localhost:5000
9. Catalog App home page will display that will show all the categories for the logged in user.
