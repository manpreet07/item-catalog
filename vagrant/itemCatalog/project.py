import json
import random
import string

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import make_response
from flask import session as login_session
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
import requests
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from functools import wraps


app = Flask(__name__)


CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Category"

#Connect to Database and create database session
engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

#===============================================================================
# # Create anti-forgery state token
#===============================================================================
@app.route('/login')
def showLogin():  
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)
 

#===============================================================================
# Method returns all categories and number of items for that category
#===============================================================================
@app.route('/')   
def allCateories():
    categoryItems = {}
    categories = session.query(Category).order_by(asc(Category.name))
    for category in categories:
        items = session.query(Item).filter_by(category_id = category.id).all()
        if len(items):
            categoryItems[category] = len(items)
        else:
            categoryItems[category] = 0 
    return render_template('home.html', categoryItems=categoryItems)
        

#===============================================================================
# Method returns all Categories for the user
#===============================================================================
@app.route('/category/')
@login_required
def showCategories():
    cItems = {}
    creator = getUserInfo(login_session['user_id'])
    categories = session.query(Category).filter_by(user_id = creator.id).order_by(asc(Category.name))
    print "categories"
    print categories
    if(categories is not None):
        for category in categories:
            items = session.query(Item).filter_by(user_id = creator.id, category_id = category.id).all()
            if len(items):
                cItems[category] = len(items)
            else:
                cItems[category] = 0
                return render_template('categories.html', categoryItems=cItems, login_session=login_session)
    else:
        return render_template('categories.html', categoryItems=None, login_session=login_session)

#===============================================================================
# Method to connect using facebook API authentication
#===============================================================================
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.5/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.5/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.5/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    return "Welcome %s" % login_session['username']


#===============================================================================
# Method to connect using Google API authentication
#===============================================================================
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id
    
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['access_token'] = credentials.access_token
    
    userId = getUserID(login_session['email'])
    
    if userId is None:
        user_id = createUser(login_session)
        login_session['user_id'] = user_id
    else:
        login_session['user_id'] = userId
            
    return "Welcome " + login_session['username']

#===============================================================================
# Method takes Login_session and returns user id
#===============================================================================
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

#===============================================================================
# Method takes User Id as parameter and returns user info
#===============================================================================
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

#===============================================================================
# Method takes email as parameter and returns user Id
#===============================================================================
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
    
#===============================================================================
# Method to disconnect
#===============================================================================
@app.route('/disconnect')
def gdisconnect():
    
    if login_session['provider'] == "facebook":
        facebook_id = login_session['facebook_id']
        # The access token must me included to successfully logout
        access_token = login_session['access_token']
        url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        login_session.clear()
        return redirect(url_for('showLogin'))
    
    if login_session['provider'] == "google":
        
        access_token = login_session['access_token']
        if access_token is None:
            print 'Access Token is None'
            response = make_response(json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        print 'result is '
        print result
        if result['status'] == '200':
            del login_session['access_token'] 
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            response = make_response(json.dumps('Successfully disconnected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return redirect(url_for('showLogin'))
        else:
            response = make_response(json.dumps('Failed to revoke token for given user.', 400))
            response.headers['Content-Type'] = 'application/json'
            return response
        

#===============================================================================
# JSON APIs to view Category Information
#===============================================================================
@app.route('/category/<int:category_id>/item/JSON')
def CategoryitemJSON(category_id):
    category = session.query(Category).filter_by(id = category_id).one()
    items = session.query(Item).filter_by(category_id = category.id).all()
    return jsonify(Items=[i.serialize for i in items])

#===============================================================================
# JSON API to view category items
#===============================================================================
@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def ItemJSON(category_id, item_id):
    item_Item = session.query(Item).filter_by(id = item_id).one()
    return jsonify(item_Item = item_Item.serialize)

#===============================================================================
# JSON API to view categories 
#===============================================================================
@app.route('/category/JSON')
def CategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories= [r.serialize for r in categories])

#===============================================================================
# JSON API to view categories and items
#===============================================================================
@app.route('/categories.json')
def allCategoriesItemsJSON():
    categories = session.query(Category).all()
    serializedCategories = []
    for i in categories:
        new_cat = i.serialize
        items = session.query(Item).filter_by(category_id = i.id).all()
        serializedItems = []
        for j in items:
            serializedItems.append(j.serialize)
        new_cat['items'] = serializedItems
        serializedCategories.append(new_cat)
    return jsonify(categories=[serializedCategories])


#===============================================================================
# Method to create new category
#===============================================================================
@app.route('/category/new/', methods=['GET','POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        if request.form['name']:
            newCategory = Category(user_id = login_session['user_id'], name = request.form['name'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html', login_session=login_session)

#===============================================================================
# Method to edit category
#===============================================================================
@app.route('/category/<int:category_id>/edit/', methods = ['GET', 'POST'])
@login_required
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            session.add(editedCategory)
            flash('Category Successfully Edited %s' % editedCategory.name)
            session.commit()
            return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category = editedCategory, login_session=login_session)


#===============================================================================
# Method to delete category
#===============================================================================
@app.route('/category/<int:category_id>/delete/', methods = ['GET','POST'])
@login_required
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id = category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('%s Successfully Deleted' % categoryToDelete.name)
        return redirect(url_for('showCategories', category_id = category_id))
    else:
        return render_template('deleteCategory.html', category = categoryToDelete, login_session=login_session)


#===============================================================================
# Method to Show a Category item
#===============================================================================
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/')
@login_required
def showItem(category_id):
    creator = getUserInfo(login_session['user_id'])
    category = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    items = session.query(Item).filter_by(user_id = creator.id, category_id = category.id).all()
    return render_template('item.html', items = items, category = category, login_session=login_session,creator= creator)

#===============================================================================
# Method to Show item description
#===============================================================================
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/<int:item_id>/itemdescription/')
@login_required
def showItemDescription(category_id, item_id):
    creator = getUserInfo(login_session['user_id'])
    category = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    item = session.query(Item).filter_by(user_id = creator.id, category_id = category.id, id=item_id).one()
    return render_template('itemDescription.html', item = item, category = category, login_session=login_session,creator= creator)


#===============================================================================
# Method to create new item
#===============================================================================
@app.route('/category/<int:category_id>/item/new/',methods=['GET','POST'])
@login_required
def newItem(category_id):
    category = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            newItem = Item(name = request.form['name'], description = request.form['description'], price = request.form['price'], type = request.form['type'], category_id = category_id, user_id = login_session['user_id'])
            session.add(newItem)
            session.commit()
            flash('New item %s Item Successfully Created' % (newItem.name))
            return redirect(url_for('showItem', category_id = category_id))
        else:
            return redirect(url_for('showItem', category_id = category_id))
    else:
        return render_template('newItem.html', category_id = category.id, category_name=category.name, login_session=login_session)


#===============================================================================
# Method to edit item
#===============================================================================
@app.route('/category/<int:category_id>/item/<int:item_id>/edit', methods=['GET','POST'])
@login_required
def editItem(category_id, item_id):
    editedItem = session.query(Item).filter_by(user_id = login_session['user_id'], id = item_id).one()
    category = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['type']:
            editedItem.type = request.form['type']
        session.add(editedItem)
        session.commit() 
        flash('%s Successfully Edited' % (editedItem.name))
        return redirect(url_for('showItem', category_id = category.id))
    else:
        return render_template('editItem.html', category_id = category.id, item_id = editedItem.id, item = editedItem, login_session=login_session)



#===============================================================================
# Method to delete item
#===============================================================================
@app.route('/category/<int:category_id>/item/<int:item_id>/delete', methods = ['GET','POST'])
@login_required
def deleteItem(category_id,item_id):
    category = session.query(Category).filter_by(user_id = login_session['user_id'], id = category_id).one()
    itemToDelete = session.query(Item).filter_by(user_id = login_session['user_id'], id = item_id).one() 
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('item Item Successfully Deleted')
        return redirect(url_for('showItem', category_id = category.id))
    else:
        return render_template('deleteItem.html', item = itemToDelete, category_id=category_id, login_session=login_session)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
