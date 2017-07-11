import string
import random
import json
import httplib2
import requests
from functools import wraps
from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Item, Category, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# --------------------------------------
# Database operations
# --------------------------------------
# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# --------------------------------------
# Login Functions
# --------------------------------------
# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function


# Login route, create anit-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Connect FB login
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
    url = 'https://graph.facebook.com/oauth/access_token?grant_type'
    + '=fb_exchange_token&client_id=%s'
    + '&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.8/me?'
    + 'fields=id%2Cname%2Cemail%2Cpicture&access_token=' + access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session
    # in order to properly logout
    login_session['access_token'] = access_token

    # Get user picture
    login_session['picture'] = data["picture"]["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    + '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'], 'success')
    return output


# CONNECT - Google login get token
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
        return response

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
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['picture'] = data['picture']

    # see if user exists, if not create new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'], 'success')
    print "done!"
    return output


# --------------------------------------
# Logout functions
# --------------------------------------
# Disconnect from google
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # token given is invalid
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect from facebook
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?'
    + 'access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    print login_session
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session:
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in", 'danger')
        return redirect(url_for('showCatalog'))


# --------------------------------------
# CRUD operations for categories
# --------------------------------------
# READ - default page for both logged in and logged out users,
# show latest items and categories
@app.route('/')
@app.route('/categories/')
def showCatalog():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.id.desc())
    quantity = items.count()

    # If user not logged in, show the public catalog page,
    # else show the regular page
    if 'username' not in login_session:
        return render_template(
            'public_catalog.html',
            categories=categories, items=items, quantity=quantity)
    else:
        return render_template(
            'catalog.html',
            categories=categories, items=items, quantity=quantity)


# CREATE - New category
@app.route('/categories/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        # If user id is not in session, but email is,
        # try and get the userid using email address
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserID(login_session['email'])

        # Create new category
        newCategory = Category(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("Successfully created category!", 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new_category.html')


# EDIT a category
@app.route('/categories/<string:category_name>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    # Get category by ID
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()

    # Check if current logged in user is the owner of the category,
    # if not, return error message
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert"
        + "('You are not authorized!')}</script><body onload='myFunction()'>"

    # Update category
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash(
                'Successfully saved category!', 'success')
            return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'edit_category.html', category=editedCategory)


# DELETE a category
@app.route(
    '/categories/<string:category_name>/delete/',
    methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    # Get category by ID
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()

    # Check if current logged in user is the owner of the category,
    # if not, return error message
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert"
        + "('You are not authorized!')}</script><body onload='myFunction()'>"

    # Delete category
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('Successfully deleted category!', 'success')
        session.commit()
        return redirect(
            url_for('showCatalog'))
    else:
        return render_template(
            'delete_category.html', category=categoryToDelete)


# --------------------------------------
# CRUD operations for items
# --------------------------------------
# READ - show items for a specific category
@app.route('/categories/<string:category_name>/')
@app.route('/categories/<string:category_name>/items/')
def showCategoryItems(category_name):
    # Get category by name
    category = session.query(Category).filter_by(name=category_name).one()

    # Get all categories in system, this is needed since we are displaying
    # all categories on the left category pane and only filtering the
    # items for a specific category on the right pane
    categories = session.query(Category).all()

    # Get the owner for the category
    creator = getUserInfo(category.user_id)

    # Get all the items for the specific category and count
    items = session.query(
        Item).filter_by(
            category_id=category.id).order_by(Item.id.desc())
    quantity = items.count()

    # Finally, render the page and pass data needed
    return render_template(
        'category.html',
        categories=categories,
        category=category,
        items=items,
        quantity=quantity,
        creator=creator)


# READ - Show item info
@app.route('/categories/<string:category_name>/<string:item_name>/')
def showItem(category_name, item_name):
    # Get item category by ID
    category = session.query(Category).filter_by(name=category_name).one()

    # Get item and item owneer
    item = session.query(
        Item).filter_by(name=item_name).one()

    creator = getUserInfo(category.user_id)

    # Finally, render the page and pass data needed
    return render_template(
        'item.html',
        category=category, item=item, creator=creator)


# CREATE - Create new item
@app.route('/categories/item/new', methods=['GET', 'POST'])
@login_required
def newItem():
    # Get all categories in system
    categories = session.query(Category).all()

    if request.method == 'POST':
        # Create new item object
        addNewItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            category_id=request.form['category'],
            user_id=login_session['user_id'])

        # Save item to db
        session.add(addNewItem)
        session.commit()
        flash("Successfully created item!", 'success')

        # Redirect to main catalog page
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new_item.html', categories=categories)


# UPDATE - Update an item
@app.route('/<string:item_name>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item_name):
    # Get item to be updated
    editedItem = session.query(
        Item).filter_by(name=item_name).one()

    # Check if currently logged in user is item owner,
    # if not, return error message
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert"
        + "('You are not authorized!')}</script><body onload='myFunction()'>"

    # Perform item update and redirect to catalog page
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash("Successfully saved item!", 'success')
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).all()
        return render_template(
            'edit_item.html',
            categories=categories,
            item=editedItem)


# DELETE - Delete an item
@app.route('/<string:item_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item_name):
    # Get item to be deleted
    itemToDelete = session.query(
        Item).filter_by(name=item_name).one()

    # Check if currently logged in user is item owner,
    # if not, return error message
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert"
        + "('You are not authorized!')}</script><body onload='myFunction()'>"

    # Perform item update and redirect to catalog page
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Successfully deleted item!', 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'delete_item.html', item=itemToDelete)


# --------------------------------------
# User operations
# --------------------------------------
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()

    return user


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# --------------------------------------
# JSON APIs
# --------------------------------------
@app.route('/api/v1/categories/JSON')
def categoriesJSON():
    # Returns JSON string of all categories in system
    categories = session.query(Category).all()
    return jsonify(Categories=[r.serialize for r in categories])


@app.route('/api/v1/items/JSON')
def itemsJSON():
    # Returns JSON string of all items in system
    items = session.query(Item).order_by(Item.id.desc())
    return jsonify(Items=[i.serialize for i in items])


@app.route('/api/v1/categories/<string:category_name>/items/JSON')
def categoryItemsJSON(category_name):
    # Get category
    category = session.query(Category).filter_by(name=category_name).one()

    # Returns JSON string of all items for a category
    items = session.query(
        Item).filter_by(
            category_id=category.id).order_by(Item.id.desc())
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/api/v1/categories/<string:category_name>/<string:item_name>/JSON')
def itemJSON(category_name, item_name):
    # Returns JSON string of one item
    mItem = session.query(
        Item).filter_by(name=item_name).one()
    return jsonify(Item=mItem.serialize)


# --------------------------------------
# Main function
# --------------------------------------
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
