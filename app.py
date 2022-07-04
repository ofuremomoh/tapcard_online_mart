from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from elasticsearch import Elasticsearch
from flask import render_template

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import current_user, login_user, logout_user
from flask_wtf import FlaskForm
from flask import request
from wtforms import Form, StringField, PasswordField, BooleanField, SubmitField, SelectField, DecimalField, IntegerField, FormField, FieldList
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, NumberRange
import phonenumbers

from flask import render_template, flash, redirect, url_for, request, g
from flask_uploads import UploadSet, configure_uploads, IMAGES
import os




app = Flask(__name__)

#add_item Upload Configurations 
photos = UploadSet('photos',IMAGES)

app.config['UPLOADED_PHOTOS_DEST'] = 'static/images'
app.config['ELASTICSEARCH_URL']  = 'http://localhost:9200'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']  = False
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['ITEMS_PER_PAGE'] = 10
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:CoreSocial94!@localhost:5433/veralith'
app.config['UPLOADED_PHOTOS_URL'] = 'http://127.0.0.1:5000/static/img/'



    
configure_uploads(app,photos)

basedir = os.path.abspath(os.path.dirname(__file__))

#universal content rendering
@app.before_request
def before_request():
    g.search_form = SearchForm()


app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)






app.elasticsearch = Elasticsearch([app.config['ELASTICSEARCH_URL']]) \
    if app.config['ELASTICSEARCH_URL'] else None

#### Errors ###
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


### Forms #####


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])

    password = PasswordField('Password', validators=[DataRequired()])
    usertype = SelectField('User Type', choices=[('Vendor', 'Vendor'), ('Customer', 'Customer')])
    remember = BooleanField('Remember Me')
    submit   = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username    = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=32, message="Username must be between 3 and 32 characters.")])

    email       = StringField('Email', validators=[
        DataRequired(), 
        Email(message="Invalid email address.")])

    phone       = StringField('Phone Number', validators=[DataRequired()])
    address     = StringField('Address', validators=[DataRequired()])
    firstname   = StringField('First Name', validators=[DataRequired()])
    lastname    = StringField('Last Name', validators=[DataRequired()])
    usertype    = SelectField('User Type', choices=[('Vendor', 'Vendor'), ('Customer', 'Customer')])
    password    = PasswordField('Password', validators=[DataRequired()])
    password2   = PasswordField('Verify Password', validators=[DataRequired(), EqualTo('password')])
    
    submit      = SubmitField('Sign Up')

    #local field validators
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('That username is taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('An account using that email already exists.')

    def validate_phone(self, phone):
        try:
            number = phonenumbers.parse(phone.data, None)
            if not phonenumbers.is_possible_number(number):
                raise ValidationError('Invalid phone number.')

        except:
            number = phonenumbers.parse("+1"+phone.data, None)
            if not phonenumbers.is_possible_number(number):
                raise ValidationError('Invalid phone number.')

class AddToCartForm(FlaskForm):
    submit = SubmitField('Add to Cart')

class QuantityEntryForm(FlaskForm):
    quantity = IntegerField(validators=[DataRequired()])

    def validate_quantity(self, quantity):
        if quantity.data < 0:
            raise ValidationError('Invalid quantity.')

class CartQuantitiesForm(FlaskForm):
    quantities = FieldList(FormField(QuantityEntryForm), min_entries=1)
    submit = SubmitField('Done')


#elasticsearch form
class SearchForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        if 'formdata' not in kwargs:
            kwargs['formdata'] = request.args
        if 'csrf_enabled' not in kwargs:
            kwargs['csrf_enabled'] = False
        super(SearchForm, self).__init__(*args, **kwargs)

#addItem to Inventory form
class ItemForm(FlaskForm):
    name        = StringField('Name',validators=[DataRequired()])
    price       = DecimalField('Price',validators=[
        DataRequired(), 
        NumberRange(min=0.01, message="Must have a positive price.")])
    description = StringField('Description',validators=[
        DataRequired(), 
        Length(max=300)])
    stock       = IntegerField('Stock',validators=[
        DataRequired(), 
        NumberRange(min=1, message="Must have stock.")])
    submit      = SubmitField('Submit',validators=[DataRequired()])


#### Models #####

class SearchableMixin(object):
    '''
    When SearchableMixin is included for inheritance on another object, it is given 
    searchability in the Elasticsearch cluster. .reindex() must be called to initialize
    searchability on objects that are retroactively given SearchableMixin.
    '''
    
    @classmethod
    def search(cls, expression, page, per_page):
        ids, total = query_index(cls.__tablename__, expression, page, per_page)
        if total == 0 or not len(ids):
            return cls.query.filter_by(id=0), 0
        
        when = []
        for i in range(len(ids)):
            when.append((ids[i], i))
        
        #return cls.query.filter(cls.id.in_(ids)).order_by(db.case(when, value=cls.id)), total
        return cls.query.filter(cls.id.in_(ids)).order_by(
            db.case(when, value=cls.id)), total

    @classmethod
    def before_commit(cls, session):
        #figure out what the current db.session's state is
        session._changes = {
            'add': list(session.new),
            'update': list(session.dirty),
            'delete': list(session.deleted)
        }
    
    @classmethod
    def after_commit(cls, session):
        for obj in session._changes['add']:
            if isinstance(obj, SearchableMixin):
                add_to_index(obj.__tablename__, obj)
        for obj in session._changes['update']:
            if isinstance(obj, SearchableMixin):
                add_to_index(obj.__tablename__, obj)
        for obj in session._changes['delete']:
            if isinstance(obj, SearchableMixin):
                remove_from_index(obj.__tablename__, obj)
        
        session._changes = None

    @classmethod
    def reindex(cls):
        for obj in cls.query:
            add_to_index(obj.__tablename__, obj)

#listen to SQLAlchemy commits so the elasticsearch indices are always updated on database changes
db.event.listen(db.session, 'before_commit', SearchableMixin.before_commit)
db.event.listen(db.session, 'after_commit', SearchableMixin.after_commit)

class User(UserMixin, db.Model):
    '''
    All site users are included on this table.
    '''

    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(64), index=True, unique=True)
    email           = db.Column(db.String(120), index=True, unique=True)
    firstname       = db.Column(db.String(64))
    lastname        = db.Column(db.String(64))
    phone           = db.Column(db.String(16))
    usertype        = db.Column(db.String(16))
    address         = db.Column(db.String(64))
    password_hash   = db.Column(db.String(128))
    items           = db.relationship('Item', backref='vendor', lazy='dynamic')

    cart            = db.relationship('Cart', uselist=False, back_populates='customer')

    def initialize_cart(self):
        newcart = Cart(customer=self, cartprice=0.0)
        db.session.add(newcart)
        db.session.commit()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}: {} {}>'.format(self.username, self.firstname, self.lastname)   

class Item(SearchableMixin, db.Model):
    '''
    Item defines the table of products for sale. Item.vendor accesses the seller of an Item.
    '''

    __searchable__ = ['title', 'description']
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(64))
    description = db.Column(db.String(300))
    price       = db.Column(db.Float)
    stock       = db.Column(db.Integer)
    featured    = db.Column(db.Boolean)
    image       = db.Column(db.String(64))
    vendorid    = db.Column(db.Integer, db.ForeignKey('user.id'))
    cartitem    = db.relationship('CartItem', backref='item', lazy='dynamic')
    order       = db.relationship('Order', backref='item', lazy='dynamic')
    tags        = db.relationship('ItemTag', backref='item', lazy='dynamic')

    def toggle_feature(self):
        self.featured = not self.featured
        db.session.commit()
        return self.featured

    def __repr__(self):
        return '<Item {} sold by {}>'.format(self.title, User.query.get(self.vendorid).username)

#cart system models
class Cart(db.Model):
    '''
    Cart defines the table of carts in the database. Every customer has one Cart.
    A customer's Cart is accessible through the .cart attribute on a User of type 'Customer' 
    '''

    id          = db.Column(db.Integer, primary_key=True)
    customerid  = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer    = db.relationship('User', back_populates='cart')
    cartprice   = db.Column(db.Float)
    items       = db.relationship('CartItem', backref='cart', lazy='dynamic')

    def add_item(self, item):
        '''
        Add Item >item< to cart. 
        '''
        
        cartitem = CartItem.query.filter_by(cartid=self.id, itemid=item.id).first()
        if cartitem:
            cartitem.quantity += 1
        else:
            db.session.add(CartItem(cart=self, item=item, quantity=1))

        db.session.commit()
        self.update_price()

    def set_quantity(self, item, quantity):
        '''
        Directly set a >quantity< of Item argument >item<. 
        Doesn't work if the Item is not found in the Cart.
        '''

        cartitem = CartItem.query.filter_by(cartid=self.id, itemid=item.id).first()
        if cartitem:
            if quantity <= 0:
                return self.remove_item(item)
            cartitem.quantity = quantity
            db.session.commit()
            self.update_price()

    def remove_item(self, item):
        '''
        Remove an item from the cart based on an Item passed as an argument, >item<.
        '''

        cartitem = CartItem.query.filter_by(cartid=self.id, itemid=item.id).first()
        if cartitem:
            db.session.delete(cartitem)
            db.session.commit()
            self.update_price()
        return True

    def update_price(self):
        '''
        Internal cart function. Call this whenever you change the cart's contents.
        Iterate over items in cart and compute price.
        '''

        cartitems = CartItem.query.filter_by(cartid=self.id)
        total_price = 0.0
        for cartitem in cartitems:
            total_price += cartitem.item.price * cartitem.quantity
        
        self.cartprice = total_price
        db.session.commit()

    def checkout(self):
        '''
        Perform managerial cart checkout tasks with this cart's items.
        Do NOT call this function unless the checkout is deemed valid elsewhere.
        No validation is done here. 
        '''

        cartitems = CartItem.query.filter_by(cartid=self.id)
        for cartitem in cartitems:
            db.session.add(Order(
                item=cartitem.item,
                quantity=cartitem.quantity,
                price=(cartitem.item.price*cartitem.quantity),
                customer=self.customer,
                vendor=cartitem.item.vendor,
                name=(self.customer.firstname+" "+self.customer.lastname),
                address=self.customer.address
            ))
            item = Item.query.get(cartitem.itemid)
            item.stock -= cartitem.quantity
            db.session.delete(cartitem)
        
        db.session.commit()
        self.update_price()
        


class CartItem(db.Model):
    '''
    Every time an item is added to a cart, a CartItem is added to the CartItems table.
    Entries in this table define a relationship between an Item and a Cart. 
    '''

    id          = db.Column(db.Integer, primary_key=True)
    quantity    = db.Column(db.Integer)
    itemid      = db.Column(db.Integer, db.ForeignKey('item.id'))
    cartid      = db.Column(db.Integer, db.ForeignKey('cart.id'))

class Order(db.Model):
    '''
    Whenever a Cart.checkout() is successfully completed, an Order is created for each CartItem.
    Vendors can see the list of Orders they've gotten on their profile page.
    '''

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(64))
    address         = db.Column(db.String(128))
    quantity        = db.Column(db.Integer)
    price           = db.Column(db.Float)
    itemid          = db.Column(db.Integer, db.ForeignKey('item.id'))
    customerid      = db.Column(db.Integer, db.ForeignKey('user.id'))
    vendorid        = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    customer        = db.relationship('User', foreign_keys=[customerid])
    vendor          = db.relationship('User', foreign_keys=[vendorid])

#tagging system models
class Tag(SearchableMixin, db.Model):
    '''
    Part of planned Tagging system. Currently unused.
    '''
    __searchable__ = ['title']
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(64), index=True, unique=True)
    itemtags    = db.relationship('ItemTag', backref='tag', lazy='dynamic')

class ItemTag(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    itemid  = db.Column(db.Integer, db.ForeignKey('item.id'))
    tagid   = db.Column(db.Integer, db.ForeignKey('tag.id'))


        

@login.user_loader
def load_user(id):
    return User.query.get(int(id))




#homepage
@app.route('/')
@app.route('/index')
def index():
    
    return render_template('index.html', title="Front Page", featured=Item.query.filter_by(featured=True))

#login page
@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        #this fails if:
        ##the user doesnt exist
        ##the password is wrong (check_password)
        ##the selected usertype is wrong (want users to always know what they're logging in as, even if it's redundant)
        ##the usertype selection doesn't matter if you're logging in as an admin though
        if not user or not user.check_password(form.password.data) or (user.usertype != form.usertype.data and user.usertype != 'Admin'):
            flash('No such user exists.', 'error')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember.data)
        return redirect(url_for('index'))
    return render_template('login.html', title="Login Page", form=form)

#logout page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

#register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, 
            email=form.email.data, 
            phone=form.phone.data,
            address=form.address.data,
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            usertype=form.usertype.data)
            
        user.set_password(form.password.data)
        user.initialize_cart()
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login')) 
    return render_template('register.html', title='Register', form=form)

#product page routing
@app.route('/product/<pid>', methods=['GET', 'POST'])
def product(pid):
    item = Item.query.filter_by(id=pid).first()
    if item:
        form = AddToCartForm()
        if request.method == 'POST' and not request.args.get('featuring'):
            current_user.cart.add_item(item)
            flash('Add to cart successful.')
            return redirect(url_for('cart')) 
        elif request.args.get('featuring'):
            if item.toggle_feature():
                flash('Item featured successfully.')
            else:
                flash('Item removed from featured items successfully.')
            return redirect(url_for('index'))
        
        vendorname = item.vendor.firstname + " " + item.vendor.lastname
        photourl = photos.url(item.image)
        return render_template('product.html', item=item, form=form, vendorname=vendorname, photourl=photourl)

    else:
        return render_template('404.html')


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if current_user.is_anonymous:
        flash('You must register to buy items!', 'error')
        return redirect(url_for('register')) 

    elif current_user.usertype == 'Vendor' or current_user.usertype == 'Admin':
        flash('You must be a customer to buy items!', 'error')
        return redirect(url_for('index'))

    else:
        editing = False
        form = None
        cart = Cart.query.filter_by(customerid=current_user.id).first()
        if request.args.get('removed'):
            flash('Item removed from cart.')
            cart.remove_item(Item.query.get(request.args.get('removed')))
            return redirect(url_for('cart'))

        cartitems = CartItem.query.filter_by(cartid=cart.id)

        if request.args.get('edit'):
            editing = True
            quantities = []
            for cartitem in cartitems:
                temp = {}
                temp["quantity"] = cartitem.quantity
                quantities.append(temp)
            form = CartQuantitiesForm(quantities=quantities)
        
        if form and request.method == 'POST':
            for i, cartitem in enumerate(cartitems):
                current_user.cart.set_quantity(cartitem.item, form.quantities[i].quantity.data)

            flash('Quantities saved.')
            return redirect(url_for('cart'))

        return render_template('cart.html', cartitems=cartitems, ccart=cart, editing=editing, form=form)

@app.route('/cart/checkout', methods=['GET','POST'])
def checkout():
    if not current_user.is_anonymous and current_user.usertype=='Customer':
        cart = Cart.query.filter_by(customerid=current_user.id).first()
        cartitems = CartItem.query.filter_by(cartid=cart.id)
        if cartitems:
            error_str = 'Vendor does not have enough items to fulfill order for: '
            errors = 0
            for cartitem in cartitems:
                if cartitem.quantity >= cartitem.item.stock:
                    error_str += cartitem.item.title + ', '
                    errors += 1

        else:
            error_str += 'Cart is empty.  '
            errors += 1

        if errors > 0:
            flash(error_str[:-2], 'error')
            return redirect(url_for('cart'))
        
        else:
            cart.checkout()
            flash('Purchase successful. Vendors have been notified.')
            return redirect(url_for('index'))
    
    else:
        return redirect(url_for('index'))


@app.route('/search')
def search():
    if not g.search_form.validate():
        return redirect(url_for('index'))
    items, total = Item.search(g.search_form.query.data, 1, 10)
    
    return render_template('search.html', items=items)

##vendor stuff
#add_item page
@app.route('/add_item',methods=["GET","POST"])
def add_item():
        form = ItemForm()
        if request.method == 'POST' and request.files and 'photo' in request.files and form.validate_on_submit():
            filename = photos.save(request.files['photo'])
            #url = photos.url(filename)
            item = Item(title=form.name.data,
                price=form.price.data,
                description=form.description.data,
                stock=form.stock.data,
                vendorid=current_user.id,
                image=filename)
            db.session.add(item)
            db.session.commit()
            flash("Congratulations, your item has been added")
            return redirect(url_for('inventory',username=current_user.username))
        else:
            return render_template('add_item.html', title="Add Item", form=form)

#inventory page
@app.route('/inventory',methods=["GET"])
def inventory():
    if not current_user.is_anonymous and current_user.usertype == 'Vendor':
        items = Item.query.filter_by(vendorid = current_user.id).all()
        if request.args.get('removed'):
            flash('Item removed from your inventory.')
            db.session.delete(Item.query.get(request.args.get('removed')))
            cartitems = CartItem.query.filter_by(itemid=request.args.get('removed'))
            for cartitem in cartitems:
                db.session.delete(cartitem)
            db.session.commit()
            return redirect(url_for('inventory'))
        return render_template('inventory.html',items = items)

##profile pages
#vendor page
@app.route('/vendor/<username>', methods=['GET', 'POST'])
def vendor(username):
    user = User.query.filter_by(username=username).first()
    if request.args.get('completed'):
        flash('Order marked as complete.')
        db.session.delete(Order.query.get(request.args.get('completed')))
        db.session.commit()

        return redirect(url_for('vendor', username=username))

    if user and user.usertype == 'Vendor':
        if current_user.username == user.username:
            orders = Order.query.filter_by(vendor=current_user)
            items = []
        else:
            orders = []
            items = Item.query.filter_by(vendor=user)

        return render_template('vendor.html', vendor=user, items=items, orders=orders)

    else:
        return render_template('404.html')

#customer page
@app.route('/user/<username>')
def customer(username):
    user = User.query.filter_by(username=username).first()
    if user and user.usertype == 'Customer':
        return render_template('customer.html', customer=user)

    else:
        return render_template('404.html')

#admin page
@app.route('/admin/<username>')
def admin(username):
    user = User.query.filter_by(username=username).first()
    if user and user.usertype == 'Admin':
        if current_user.is_anonymous or current_user.usertype != 'Admin':
            return render_template('403.html')
        
        else:
            return render_template('admin.html', admin=user, users=User.query.all())
    
    else:
        return render_template('404.html')

#### Search 


def add_to_index(index, model):
    #currently, elasticsearch will always be running so this conditional isn't necessary
    if not app.elasticsearch:
        return
    
    payload = {}
    for field in model.__searchable__:
        payload[field] = getattr(model, field)
    app.elasticsearch.index(index=index, doc_type=index, id=model.id, body=payload)

def remove_from_index(index, model):
    if not app.elasticsearch:
        return
    app.elasticsearch.delete(index=index, doc_type=index, id=model.id)

def query_index(index, query, page, per_page):
    if not app.elasticsearch:
        return [], 0

    #generate elasticsearch search object
    #search will return a JSON object with the search diagnostics
    search = app.elasticsearch.search(
        index=index,
        #doc_type=index,
        body = {
            'query': {
                'multi_match': {
                    'query': query, 
                    'fields': ['*']
                }
            },
            'from': (page - 1) * per_page,
            'size': per_page
        }
    )

    #all we care about are the list of IDs of objects in the 'hits' field of the JSON object
    ids = [int(hit['_id']) for hit in search['hits']['hits']]
    return ids, search['hits']['total']



@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Item': Item}




if __name__ == "__main__":
    app.run(debug = True)
