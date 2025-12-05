from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os
from werkzeug.utils import secure_filename
import gridfs
from bson.objectid import ObjectId
import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# MongoDB Configuration
import certifi

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://harikothapalli61_db_user:Kitten%402024@cluster0.cyuxuoa.mongodb.net/mens_shop?appName=Cluster0')
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client.get_database()
fs = gridfs.GridFS(db)

# Ensure collections exist
if 'users' not in db.list_collection_names():
    db.create_collection('users')
if 'products' not in db.list_collection_names():
    db.create_collection('products')
if 'orders' not in db.list_collection_names():
    db.create_collection('orders')
if 'reviews' not in db.list_collection_names():
    db.create_collection('reviews')
if 'wishlist' not in db.list_collection_names():
    db.create_collection('wishlist')
if 'categories' not in db.list_collection_names():
    db.create_collection('categories')
if 'user_activity' not in db.list_collection_names():
    db.create_collection('user_activity')

# CSRF Protection (Basic Implementation)
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Helper for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Recommendation Logic
def get_user_recommendations(user_id):
    # 1. Get user's recent activity (searches, views - implied by orders for now)
    recent_orders = list(db.orders.find({'user_id': user_id}).sort('created_at', -1).limit(5))
    recent_searches = list(db.user_activity.find({'user_id': user_id, 'type': 'search'}).sort('timestamp', -1).limit(5))
    
    preferred_categories = set()
    
    # Extract categories from orders
    for order in recent_orders:
        for item in order['items']:
            product = db.products.find_one({'_id': ObjectId(item['product_id'])})
            if product:
                preferred_categories.add(product['category'])
                
    # Extract categories from searches (simple keyword match)
    all_categories = db.products.distinct('category')
    for activity in recent_searches:
        query = activity['query'].lower()
        for cat in all_categories:
            if cat in query:
                preferred_categories.add(cat)
    
    # Fetch products from preferred categories
    recommendations = []
    if preferred_categories:
        recommendations = list(db.products.find({
            'category': {'$in': list(preferred_categories)},
            'stock': {'$gt': 0}
        }).limit(8))
        
    # Fallback: Popular products (if no specific preference found or few results)
    if len(recommendations) < 4:
        # Simple logic: products with most stock or just random for now
        popular = list(db.products.find({'stock': {'$gt': 0}}).limit(8))
        recommendations.extend(popular)
        
    # Deduplicate
    seen = set()
    unique_recs = []
    for p in recommendations:
        if p['_id'] not in seen:
            unique_recs.append(p)
            seen.add(p['_id'])
            
    return unique_recs[:4] # Return top 4

# Routes
@app.route('/')
def index():
    query = {}
    search_query = request.args.get('q', '')
    if search_query:
        query['$or'] = [
            {'name': {'$regex': search_query, '$options': 'i'}},
            {'description': {'$regex': search_query, '$options': 'i'}},
            {'brand': {'$regex': search_query, '$options': 'i'}}, # Search in brand too
            {'color': {'$regex': search_query, '$options': 'i'}}, # Search in color too
            {'fabric': {'$regex': search_query, '$options': 'i'}} # Search in fabric too
        ]
        
        # Track Search if Logged In
        if 'user_id' in session:
            db.user_activity.insert_one({
                'user_id': session['user_id'],
                'type': 'search',
                'query': search_query,
                'timestamp': datetime.datetime.now()
            })
    
    # Filters
    category_filter = request.args.get('category')
    brand_filter = request.args.get('brand')
    color_filter = request.args.get('color')
    fabric_filter = request.args.get('fabric')
    size_filter = request.args.get('size')

    if category_filter:
        query['category'] = category_filter
    if brand_filter:
        query['brand'] = brand_filter
    if color_filter:
        query['color'] = color_filter
    if fabric_filter:
        query['fabric'] = fabric_filter
    if size_filter:
        # Size is stored in 'sizes' array of objects: [{'size': 'M', 'stock': 10}, ...]
        # We need to match if ANY element in the array has size == size_filter
        query['sizes.size'] = size_filter
        
    # Sorting
    sort_by = request.args.get('sort', 'newest')
    sort_criteria = [('_id', -1)] # Default to newest
    
    if sort_by == 'price_asc':
        sort_criteria = [('price', 1)]
    elif sort_by == 'price_desc':
        sort_criteria = [('price', -1)]
        
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 12
    skip = (page - 1) * per_page
    
    total_products = db.products.count_documents(query)
    total_pages = (total_products + per_page - 1) // per_page
    
    products = list(db.products.find(query).sort(sort_criteria).skip(skip).limit(per_page))
    
    # Get all distinct values for sidebar filters, respecting the current category
    sidebar_query = {}
    if category_filter:
        sidebar_query['category'] = category_filter
        
    categories = db.products.distinct('category') # Categories should always be all visible
    brands = db.products.distinct('brand', sidebar_query)
    colors = db.products.distinct('color', sidebar_query)
    fabrics = db.products.distinct('fabric', sidebar_query)
    # distinct sizes is a bit trickier because it's a list of dicts. 
    # MongoDB distinct on 'sizes.size' should work.
    sizes = db.products.distinct('sizes.size', sidebar_query)
    
    # Get Recommendations
    recommendations = []
    if 'user_id' in session and not search_query and not category_filter and not brand_filter and page == 1:
        # Only show recommendations on main landing (no filters active) and first page
        recommendations = get_user_recommendations(session['user_id'])
    
    return render_template('index.html', products=products, 
                         categories=categories, brands=brands, colors=colors, fabrics=fabrics, sizes=sizes,
                         selected_category=category_filter, selected_brand=brand_filter, 
                         selected_color=color_filter, selected_fabric=fabric_filter, selected_size=size_filter,
                         current_sort=sort_by, search_query=search_query,
                         recommendations=recommendations,
                         current_page=page, total_pages=total_pages)

@app.route('/image/<image_id>')
def get_image(image_id):
    try:
        file = fs.get(ObjectId(image_id))
        return app.response_class(file.read(), mimetype=file.content_type)
    except:
        return 'Image not found', 404

# User Authentication
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        if db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
            
        user = {
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'role': 'customer'
        }
        db.users.insert_one(user)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = db.users.find_one({'email': email})
        
        if user:
            # Check password (hashed or legacy plain text)
            password_valid = False
            if user.get('password', '').startswith('scrypt:') or user.get('password', '').startswith('pbkdf2:'):
                 if check_password_hash(user['password'], password):
                     password_valid = True
            elif user.get('password') == password:
                 # Legacy plain text match - migrate to hash
                 new_hash = generate_password_hash(password)
                 db.users.update_one({'_id': user['_id']}, {'$set': {'password': new_hash}})
                 password_valid = True
                 
            if password_valid:
                session['user_id'] = str(user['_id'])
                session['user_name'] = user['name']
                session['role'] = user.get('role', 'customer')
                
                if user.get('role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password', 'error')
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/add_review/<product_id>', methods=['POST'])
@login_required
def add_review(product_id):
    rating = int(request.form['rating'])
    comment = request.form['comment']
    user_id = session['user_id']
    user_name = session['user_name']
    
    # Verify purchase and delivery
    # Check if user has an order with this product that is 'Delivered'
    has_purchased = db.orders.find_one({
        'user_id': user_id,
        'items.product_id': product_id,
        'status': 'Delivered'
    })

    if not has_purchased:
        flash('You can only review products you have purchased and received.', 'error')
        return redirect(url_for('product_detail', product_id=product_id))

    review = {
        'product_id': product_id,
        'user_id': user_id,
        'user_name': user_name,
        'rating': rating,
        'comment': comment,
        'created_at': datetime.datetime.now()
    }
    db.reviews.insert_one(review)
    flash('Review submitted successfully!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/product/<product_id>')
def product_detail(product_id):
    product = db.products.find_one({'_id': ObjectId(product_id)})
    recommendations = list(db.products.find({
        'category': product['category'],
        '_id': {'$ne': ObjectId(product_id)}
    }).limit(4))
    
    # Fetch reviews
    reviews = list(db.reviews.find({'product_id': product_id}).sort('created_at', -1))
    
    return render_template('product.html', product=product, recommendations=recommendations, reviews=reviews)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if 'cart' not in session or not session['cart']:
        return redirect(url_for('cart'))
        
    cart_items = []
    total_price = 0
    for item in session['cart']:
        product = db.products.find_one({'_id': ObjectId(item['product_id'])})
        if product:
            product['quantity'] = item['quantity']
            product['size'] = item.get('size')
            product['total'] = product['price'] * item['quantity']
            cart_items.append(product)
            total_price += product['total']
            
    if request.method == 'POST':
        # Re-fetch items to ensure we save current details (snapshot) and validate stock
        order_items = []
        calculated_total = 0
        
        for item in session['cart']:
            product = db.products.find_one({'_id': ObjectId(item['product_id'])})
            if not product:
                continue
            
            # Check stock for specific size
            size_stock_available = False
            requested_size = item.get('size')
            
            if product.get('sizes') and isinstance(product['sizes'], list) and isinstance(product['sizes'][0], dict):
                # New format: list of dicts
                for s in product['sizes']:
                    if s['size'] == requested_size:
                        if s['stock'] >= item['quantity']:
                            size_stock_available = True
                        break
            else:
                # Fallback for old format or no sizes (check total stock)
                if product['stock'] >= item['quantity']:
                    size_stock_available = True

            if not size_stock_available:
                flash(f"Sorry, {product['name']} (Size: {requested_size}) is out of stock or requested quantity unavailable.", 'error')
                return redirect(url_for('cart'))
                
            order_items.append({
                'product_id': item['product_id'],
                'name': product['name'],
                'price': product['price'],
                'quantity': item['quantity'],
                'size': requested_size,
                'image_url': product['image_url']
            })
            calculated_total += product['price'] * item['quantity']
            
            # Stock deduction moved to approve_order
            # if product.get('sizes') and isinstance(product['sizes'], list) and isinstance(product['sizes'][0], dict):
            #      # Deduct from specific size AND total stock
            #      db.products.update_one(
            #         {'_id': ObjectId(item['product_id']), 'sizes.size': requested_size},
            #         {
            #             '$inc': {'stock': -item['quantity'], 'sizes.$.stock': -item['quantity']}
            #         }
            #      )
            # else:
            #     # Fallback
            #     db.products.update_one(
            #         {'_id': ObjectId(item['product_id'])},
            #         {'$inc': {'stock': -item['quantity']}}
            #     )

        # Generate Unique Order ID
        order_id = f"ORD-{datetime.datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:4].upper()}"

        # Create Order
        order = {
            'order_id': order_id,
            'user_id': session.get('user_id'),
            'items': order_items, # Save full details
            'total_amount': calculated_total,
            'shipping_details': {
                'name': request.form['name'],
                'address': request.form['address'],
                'city': request.form['city'],
                'zip': request.form['zip']
            },
            'payment_method': 'COD',
            'payment_status': 'Pending',
            'status': 'Pending Approval',
            'created_at': datetime.datetime.now()
        }
        db.orders.insert_one(order)
        session.pop('cart', None)
        return redirect(url_for('success'))
        
    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)


@app.route('/my_orders')
@login_required
def my_orders():
    user_id = session.get('user_id')
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    
    total_orders = db.orders.count_documents({'user_id': user_id})
    total_pages = (total_orders + per_page - 1) // per_page
    
    orders = list(db.orders.find({'user_id': user_id}).sort('_id', -1).skip(skip).limit(per_page)) 
    return render_template('my_orders.html', orders=orders, current_page=page, total_pages=total_pages)

@app.route('/order/<order_id>')
@login_required
def order_details(order_id):
    user_id = session.get('user_id')
    try:
        order = None
        # Try finding by ObjectId first (if valid)
        try:
            if ObjectId.is_valid(order_id):
                order = db.orders.find_one({'_id': ObjectId(order_id), 'user_id': user_id})
        except Exception as e:
            print(f"Invalid ObjectId: {e}")
            
        if not order:
            # Try finding by order_id string (for older orders or if passed as string)
            order = db.orders.find_one({'order_id': order_id, 'user_id': user_id})
            
        if not order:
            flash('Order not found.', 'error')
            return redirect(url_for('my_orders'))
            
        return render_template('order_details.html', order=order)
    except Exception as e:
        print(f"Error fetching order details: {e}")
        import traceback
        traceback.print_exc()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('my_orders'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    
    if request.method == 'POST':
        name = request.form.get('name')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Update Name
        if name and name != user['name']:
            db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'name': name}})
            session['user_name'] = name
            flash('Profile updated successfully.', 'success')
            
        # Update Password
        if new_password:
            if not current_password:
                flash('Please enter your current password to change it.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            else:
                # Verify current password
                password_valid = False
                if user.get('password', '').startswith('scrypt:') or user.get('password', '').startswith('pbkdf2:'):
                     if check_password_hash(user['password'], current_password):
                         password_valid = True
                elif user.get('password') == current_password:
                     password_valid = True
                     
                if password_valid:
                    hashed_password = generate_password_hash(new_password)
                    db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_password}})
                    flash('Password changed successfully.', 'success')
                else:
                    flash('Incorrect current password.', 'error')
                    
        return redirect(url_for('profile'))
        
        return redirect(url_for('profile'))
    
    # Fetch recent orders for the profile page
    recent_orders = list(db.orders.find({'user_id': user_id}).sort('_id', -1).limit(5))
        
    return render_template('profile.html', user=user, orders=recent_orders)

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/update_cart/<product_id>', methods=['POST'])
def update_cart(product_id):
    if 'cart' in session:
        quantity = int(request.form.get('quantity'))
        size = request.form.get('size')
        if size == 'None':
            size = None
        color = request.form.get('color')
        
        for item in session['cart']:
            if item['product_id'] == product_id and item.get('size') == size:
                item['quantity'] = quantity
                break
        session.modified = True
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_items = []
    total_price = 0
    if 'cart' in session:
        for item in session['cart']:
            product = db.products.find_one({'_id': ObjectId(item['product_id'])})
            if product:
                product['quantity'] = item['quantity']
                product['size'] = item.get('size')
                product['total'] = product['price'] * item['quantity']
                cart_items.append(product)
                total_price += product['total']
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = []
    
    product = db.products.find_one({'_id': ObjectId(product_id)})
    size = request.form.get('size')
    
    # Validate size selection if product has sizes
    if product and product.get('sizes') and not size:
        flash('Please select a size.', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
        
    # Check stock availability for size
    if product:
        stock_available = False
        if product.get('sizes') and isinstance(product['sizes'], list) and isinstance(product['sizes'][0], dict):
             for s in product['sizes']:
                 if s['size'] == size:
                     if s['stock'] > 0:
                         stock_available = True
                     break
        else:
            # Fallback
            if product['stock'] > 0:
                stock_available = True
                
        if not stock_available:
             flash('Selected size is out of stock.', 'error')
             return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if item with same size already in cart
    found = False
    for item in session['cart']:
        if item['product_id'] == product_id and item.get('size') == size:
            item['quantity'] += 1
            found = True
            break
    
    if not found:
        session['cart'].append({'product_id': product_id, 'quantity': 1, 'size': size})
    
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<product_id>/<size>')
def remove_from_cart(product_id, size):
    if 'cart' in session:
        # Remove specific item with matching id and size
        # Handle 'None' string if size is missing (for legacy items)
        if size == 'None':
            size = None
            
        session['cart'] = [
            item for item in session['cart'] 
            if not (item['product_id'] == product_id and str(item.get('size')) == str(size))
        ]
        session.modified = True
    return redirect(url_for('cart'))

@app.route('/wishlist')
@login_required
def wishlist():
    user_id = session.get('user_id')
    wishlist_items = []
    
    # Find wishlist document for user
    user_wishlist = db.wishlist.find_one({'user_id': user_id})
    
    if user_wishlist and 'products' in user_wishlist:
        for product_id in user_wishlist['products']:
            product = db.products.find_one({'_id': ObjectId(product_id)})
            if product:
                wishlist_items.append(product)
                
    return render_template('wishlist.html', wishlist_items=wishlist_items)

@app.route('/add_to_wishlist/<product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    user_id = session.get('user_id')
    
    # Check if product exists
    if not db.products.find_one({'_id': ObjectId(product_id)}):
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
        
    # Update or create wishlist
    db.wishlist.update_one(
        {'user_id': user_id},
        {'$addToSet': {'products': product_id}}, # addToSet prevents duplicates
        upsert=True
    )
    
    flash('Added to wishlist!', 'success')
    return redirect(url_for('wishlist'))

@app.route('/remove_from_wishlist/<product_id>')
@login_required
def remove_from_wishlist(product_id):
    user_id = session.get('user_id')
    
    db.wishlist.update_one(
        {'user_id': user_id},
        {'$pull': {'products': product_id}}
    )
    
    flash('Removed from wishlist.', 'success')
    return redirect(url_for('wishlist'))

@app.route('/request_return/<order_id>')
@login_required
def request_return(order_id):
    order = db.orders.find_one({'_id': ObjectId(order_id), 'user_id': session['user_id']})
    if order and order['status'] == 'Shipped':
        db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': 'Return Requested'}}
        )
        flash('Return requested successfully. Waiting for admin approval.', 'success')
    else:
        flash('Return request failed. Order must be shipped to request return.', 'error')
    return redirect(url_for('my_orders'))

def get_admin_product_ids():
    """Returns a list of product IDs (as strings) created by the current admin."""
    if 'user_id' not in session:
        return []
    products = db.products.find({'admin_id': session['user_id']}, {'_id': 1})
    return [str(p['_id']) for p in products]

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # Only show products created by this admin
    products = list(db.products.find({'admin_id': session['user_id']}))
    
    # Ensure default categories exist if collection is empty
    if db.categories.count_documents({}) == 0:
        default_categories = ['clothing', 'accessories', 'shoes']
        for cat in default_categories:
            db.categories.insert_one({'name': cat})
            
    categories = list(db.categories.find())
    return render_template('admin/dashboard.html', products=products, categories=categories)

@app.route('/admin/add_category', methods=['POST'])
def add_category():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    name = request.form.get('name')
    if name:
        name = name.lower().strip()
        if not db.categories.find_one({'name': name}):
            db.categories.insert_one({'name': name})
            flash('Category added successfully!', 'success')
        else:
            flash('Category already exists.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_product', methods=['POST'])
def add_product():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Parse sizes and stock
        sizes_input = request.form.get('sizes', '')
        sizes_list = []
        total_stock = 0
        
        if sizes_input:
            # Expected format: "S:10, M:5, L:0"
            for item in sizes_input.split(','):
                parts = item.strip().split(':')
                if len(parts) == 2:
                    size_name = parts[0].strip()
                    try:
                        size_stock = int(parts[1].strip())
                        sizes_list.append({'size': size_name, 'stock': size_stock})
                        total_stock += size_stock
                    except ValueError:
                        continue # Skip invalid numbers
        
        # Handle Multiple Images
        image_urls = []
        if 'images' in request.files:
            files = request.files.getlist('images')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_id = fs.put(file, filename=filename, content_type=file.content_type)
                    image_urls.append(url_for('get_image', image_id=str(file_id)))
        
        # Fallback to single image upload field if used (backward compatibility or alternative)
        if not image_urls and 'image' in request.files:
             file = request.files['image']
             if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_id = fs.put(file, filename=filename, content_type=file.content_type)
                image_urls.append(url_for('get_image', image_id=str(file_id)))

        # Fallback to URL if provided
        if not image_urls:
             url_input = request.form.get('image_url', '')
             if url_input:
                 image_urls.append(url_input)
             
        # Default placeholder if still empty
        if not image_urls:
            image_urls.append('https://via.placeholder.com/300')

        product = {
            'name': request.form['name'],
            'category': request.form['category'],
            'brand': request.form.get('brand', ''),
            'color': request.form.get('color', ''),
            'fabric': request.form.get('fabric', ''),
            'price': float(request.form['price']),
            'description': request.form['description'],
            'image_url': image_urls[0], # Main image for backward compatibility
            'images': image_urls, # List of all images
            'stock': total_stock, # Total stock calculated from sizes
            'sizes': sizes_list, # List of {'size': 'S', 'stock': 10}
            'admin_id': session['user_id'] # Link product to the admin who created it
        }
        db.products.insert_one(product)
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_product/<product_id>')
def delete_product(product_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # Only allow deleting own products
    result = db.products.delete_one({'_id': ObjectId(product_id), 'admin_id': session['user_id']})
    if result.deleted_count == 0:
        flash('Product not found or access denied.', 'error')
    else:
        flash('Product deleted successfully.', 'success')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/orders')
def admin_orders():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    admin_product_ids = get_admin_product_ids()
    
    # Find orders that contain at least one product from this admin
    orders = list(db.orders.find({
        'items.product_id': {'$in': admin_product_ids}
    }).sort('created_at', -1))
    
    return render_template('admin/orders.html', orders=orders, admin_product_ids=admin_product_ids)

@app.route('/admin/approve_order/<order_id>')
def approve_order(order_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # In a real multi-vendor system, we'd only approve specific items.
    # For now, we'll allow the admin to approve the order if they are part of it.
    # A more complex implementation would split orders or have item-level status.
    
    # Deduct stock upon approval
    order = db.orders.find_one({'_id': ObjectId(order_id)})
    if order:
        for item in order['items']:
            product_id = item['product_id']
            quantity = item['quantity']
            size = item.get('size')
            
            # Check product structure for sizes
            product = db.products.find_one({'_id': ObjectId(product_id)})
            if product:
                 if product.get('sizes') and isinstance(product['sizes'], list) and isinstance(product['sizes'][0], dict) and size:
                     # Deduct from specific size AND total stock
                     db.products.update_one(
                        {'_id': ObjectId(product_id), 'sizes.size': size},
                        {
                            '$inc': {'stock': -quantity, 'sizes.$.stock': -quantity}
                        }
                     )
                 else:
                     # Fallback
                     db.products.update_one(
                        {'_id': ObjectId(product_id)},
                        {'$inc': {'stock': -quantity}}
                     )

    db.orders.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'Processing', 'approved_at': datetime.datetime.now()}}
    )
    flash('Order approved and processing.', 'success')
    return redirect(url_for('admin_orders'))

@app.route('/admin/reject_order/<order_id>')
def reject_order(order_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # Restore stock
    order = db.orders.find_one({'_id': ObjectId(order_id)})
    if order:
        for item in order['items']:
            # Restore to specific size if available
            if item.get('size'):
                 db.products.update_one(
                    {'_id': ObjectId(item['product_id']), 'sizes.size': item['size']},
                    {
                        '$inc': {'stock': item['quantity'], 'sizes.$.stock': item['quantity']}
                    }
                 )
            else:
                # Fallback
                db.products.update_one(
                    {'_id': ObjectId(item['product_id'])},
                    {'$inc': {'stock': item['quantity']}}
                )
                
    db.orders.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'Rejected'}}
    )
    flash('Order rejected and stock restored.', 'success')
    return redirect(url_for('admin_orders'))

@app.route('/admin/update_order_status/<order_id>', methods=['POST'])
def update_order_status(order_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    new_status = request.form.get('status')
    if new_status:
        db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': new_status}}
        )
        flash(f'Order status updated to {new_status}.', 'success')
    return redirect(url_for('admin_orders'))

@app.route('/admin/returns')
def admin_returns():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    admin_product_ids = get_admin_product_ids()
    
    orders = list(db.orders.find({
        'status': 'Return Requested',
        'items.product_id': {'$in': admin_product_ids}
    }).sort('created_at', -1))
    
    return render_template('admin/returns.html', orders=orders, admin_product_ids=admin_product_ids)

@app.route('/admin/approve_return/<order_id>')
def approve_return(order_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # Restore stock logic similar to reject_order
    order = db.orders.find_one({'_id': ObjectId(order_id)})
    if order:
        for item in order['items']:
            if item.get('size'):
                 db.products.update_one(
                    {'_id': ObjectId(item['product_id']), 'sizes.size': item['size']},
                    {
                        '$inc': {'stock': item['quantity'], 'sizes.$.stock': item['quantity']}
                    }
                 )
            else:
                db.products.update_one(
                    {'_id': ObjectId(item['product_id'])},
                    {'$inc': {'stock': item['quantity']}}
                )
                
    db.orders.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'Returned'}}
    )
    flash('Return approved and stock restored.', 'success')
    return redirect(url_for('admin_returns'))

@app.route('/admin/reject_return/<order_id>')
def reject_return(order_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    db.orders.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {'status': 'Shipped'}} # Revert to Shipped or maybe 'Return Rejected'
    )
    flash('Return request rejected.', 'success')
    return redirect(url_for('admin_returns'))

@app.route('/admin/reviews')
def admin_reviews():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    admin_product_ids = get_admin_product_ids()
    
    # Fetch reviews for products owned by this admin
    reviews = list(db.reviews.find({
        'product_id': {'$in': admin_product_ids}
    }).sort('created_at', -1))
    
    # Enrich reviews with product info if needed (though product_id is there, name might be nice)
    for review in reviews:
        product = db.products.find_one({'_id': ObjectId(review['product_id'])})
        if product:
            review['product_name'] = product['name']
            review['product_image'] = product['image_url']
            
    return render_template('admin/reviews.html', reviews=reviews)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
