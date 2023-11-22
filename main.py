import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template, redirect, url_for, session, flash
from sqlalchemy.exc import IntegrityError
from dbservice import *


app = create_app()

app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')


@app.route('/')
def landing():
    return render_template('landing.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        # Check if the role is a valid enum value
        valid_roles = [r.value for r in UserRole]
        if role not in valid_roles:
            flash('Invalid role. Please choose a valid role.', 'danger')
            return render_template('register.html', form=form)

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        try:
            new_user = User(username=username, email=email,
                            password=generate_password_hash(password), role=role)

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))

        except IntegrityError as e:
            # Rollback the session to avoid leaving the database in an inconsistent state
            db.session.rollback()

            # Check if the error is due to a duplicate username
            if 'duplicate key value violates unique constraint "user_username_key"' in str(e):
                flash(
                    'Username already exists. Please choose a different one.', 'danger')
            else:
                app.logger.error(f'Error during registration: {str(e)}')
                flash(
                    'An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html', form=form)

# ... (rest of the code)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Store username and role in the session
            session['username'] = user.username
            # Convert enum to string for session
            session['role'] = user.role.value

            flash('Login successful!', 'success')
            if user.role == UserRole.ADMIN:
                return redirect(url_for('admin_dashboard'))
            elif user.role == UserRole.USER:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html', form=form)


@app.route('/admin-dashboard')
def admin_dashboard():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()

        if user and user.role == UserRole.ADMIN:
            return render_template('admin_dashboard.html', username=username)
        else:
            flash(
                'Access denied. You do not have permission to view this page.', 'danger')
            return redirect(url_for('login'))

    return redirect(url_for('login'))


@app.route('/user-dashboard')
def user_dashboard():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()

        if user and user.role == UserRole.USER:
            return render_template('user_dashboard.html', username=username)
        else:
            flash(
                'Access denied. You do not have permission to view this page.', 'danger')
            return redirect(url_for('login'))

    return redirect(url_for('login'))


@app.route('/products')
def products():
    form = ProductForm()
    if 'username' in session:
        # Fetch products data from your database
        products = Product.query.all()
        return render_template('products.html', products=products, form=form)
    else:
        flash('Access denied. You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))


@app.route('/sales')
def sales():
    form = SaleForm()
    if 'username' in session:
        # Fetch sales data from your database
        sales = Sale.query.all()
        return render_template('sales.html', sales=sales, form=form)
    else:
        flash('Access denied. You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))


@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    form = ProductForm()

    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        buying_price = form.buying_price.data
        selling_price = form.selling_price.data
        stock_quantity = form.stock_quantity.data

        try:
            new_product = Product(name=name, description=description, buying_price=buying_price,
                                  selling_price=selling_price, stock_quantity=stock_quantity)
            db.session.add(new_product)
            db.session.commit()

            flash('Product added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding product: {str(e)}')
            flash('Error adding product. Please try again.', 'danger')

        return redirect(url_for('products'))

    return render_template('products.html', form=form)


@app.route('/add_sale', methods=['GET', 'POST'])
def add_sale():
    form = SaleForm()

    # Fetch products to populate the choices in the SaleForm
    form.product_id.choices = [(product.id, product.name)
                               for product in Product.query.all()]

    if form.validate_on_submit():
        product_id = form.product_id.data
        quantity = form.quantity.data

        product = Product.query.get(product_id)

        if product and product.stock_quantity >= quantity:
            # Reduce stock quantity of the product
            product.stock_quantity -= quantity

            try:
                new_sale = Sale(product_id=product_id, quantity=quantity)
                db.session.add(new_sale)
                db.session.commit()

                flash(
                    f'Sale recorded successfully for {product.name}!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error recording sale: {str(e)}')
                flash('Error recording sale. Please try again.', 'danger')
        else:
            flash('Invalid product or insufficient stock quantity.', 'danger')

        return redirect(url_for('sales'))

    return render_template('sales.html', form=form)



@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logout successful!', 'success')
    return redirect(url_for('landing'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
