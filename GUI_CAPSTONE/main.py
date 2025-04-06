from flask import Flask, session, render_template, request, redirect, url_for, jsonify
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import mysql.connector
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split
import joblib
import string
import smtplib
from email.mime.text import MIMEText
import secrets
from sklearn.metrics import r2_score, mean_squared_error
from bcrypt import hashpw, gensalt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)


def get_db_connection():
    return mysql.connector.connect(host="localhost", user="root", password="", database="sensor_db")


def generate_reset_code():
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def send_reset_email(email, reset_code):
    msg = MIMEText(f'One more step to change your password\n\nEnter your code: {reset_code} to the corresponding input box.')
    msg['Subject'] = 'Password Reset Code is ' + reset_code
    msg['From'] = 'fermostrapservices@gmail.com'
    msg['To'] = email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('fermostrapservices@gmail.com', 'jeiy aqbv iyqg inuv')
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if 'verification_code' in request.form:
            if (session.get('verification_code') == request.form['verification_code'] and
                session.get('verification_email') == request.form['email']):
                username = session.get('username')
                email = session.get('verification_email')
                password = session.get('password')

                conn = get_db_connection()
                cursor = conn.cursor()

                try:
                    cursor.execute("SELECT COUNT(*) FROM users")
                    user_count = cursor.fetchone()[0]

                    if user_count > 0:
                        return "Only one account can be created.", 403

                    cursor.execute(
                        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                        (username, email, password)
                    )
                    conn.commit()
                    return redirect(url_for('login'))
                except mysql.connector.Error as err:
                    return f"An error occurred: {err}", 500
                finally:
                    cursor.close()
                    conn.close()
            else:
                return "Invalid verification code.", 400

        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            return "All fields are required.", 400

        hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

        verification_code = generate_reset_code()
        if not send_reset_email(email, verification_code):
            return "Failed to send verification email.", 500

        session['username'] = username
        session['verification_email'] = email
        session['password'] = hashed_password
        session['verification_code'] = verification_code
        session['verification_expiry'] = (datetime.now() + timedelta(minutes=10)).isoformat()

        return render_template('verify.html', email=email)
    return render_template('signup.html')


@app.route('/update_email', methods=['GET', 'POST'])
def update_email():
    if request.method == 'POST':
        if 'new_email' in request.form:
            # Step 1: User submits new email and new password
            new_email = request.form.get('new_email')
            new_password = request.form.get('new_password')

            if not new_email or not new_password:
                return "New email and new password are required.", 400

            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Generate and send verification code
            verification_code = generate_reset_code()
            if not send_reset_email(new_email, verification_code):
                return "Failed to send verification email.", 500

            # Store data in session for verification
            session['new_email'] = new_email
            session['new_password'] = hashed_password
            session['verification_code'] = verification_code
            session['verification_expiry'] = (datetime.now() + timedelta(minutes=10)).isoformat()  # Code expires in 10 minutes

            # Render the verification form
            return render_template('update_email.html', verification_sent=True)

        elif 'verification_code' in request.form:
            # Step 2: User submits verification code
            verification_code = request.form.get('verification_code')

            if not verification_code:
                return "Verification code is required.", 400

            # Check if the verification code matches
            if (session.get('verification_code') == verification_code and
                datetime.now() <= datetime.fromisoformat(session.get('verification_expiry'))):
                # Update the email and password in the database
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "UPDATE users SET email = %s, password = %s WHERE id = %s",
                        (session.get('new_email'), session.get('new_password'), session.get('user_id'))
                    )
                    conn.commit()

                    # Clear session data
                    session.pop('new_email', None)
                    session.pop('new_password', None)
                    session.pop('verification_code', None)
                    session.pop('verification_expiry', None)

                    # Redirect to login page after successful update
                    return redirect(url_for('login'))
                except mysql.connector.Error as err:
                    return f"An error occurred: {err}", 500
                finally:
                    cursor.close()
                    conn.close()
            else:
                return "Invalid or expired verification code.", 400

    # Render the initial form for GET requests
    return render_template('update_email.html', verification_sent=False)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Incorrect password, please try again.", user_exists=True)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()

    return render_template('login.html', user_exists=user_count > 0)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            reset_code = generate_reset_code()
            send_reset_email(email, reset_code)
            session['reset_code'] = reset_code
            session['reset_email'] = email
            return redirect(url_for('reset_password'))
        else:
            return "Email not found.", 404

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        reset_code = request.form['reset_code']
        new_password = request.form['new_password']

        if 'reset_code' in session and reset_code == session['reset_code']:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, session['reset_email']))
            conn.commit()
            conn.close()

            session.pop('reset_code', None)
            session.pop('reset_email', None)
            return redirect(url_for('login'))
        else:
            return "Invalid reset code.", 400

    return render_template('reset_password.html')


data = {
    "Plant_Materials": [
        750, 800, 850, 800, 500, 900, 750, 850, 550, 600, 650, 500, 500, 500, 550, 550, 600, 650, 500, 500, 600, 550, 500, 500, 550, 550, 600,
        500, 550, 600, 500, 650, 600, 650, 600, 600, 550, 550, 550, 550, 550, 500, 500, 500, 500, 500, 500,
        700, 750, 800, 850, 900, 950, 1000, 720
    ],
    "Sugar": [
        750, 900, 850, 800, 500, 900, 900, 900, 550, 600, 650, 600, 700, 800, 650, 750, 700, 700, 550, 650, 650, 600, 750, 850, 700, 800, 750,
        500, 550, 600, 600, 650, 700, 700, 650, 750, 800, 750, 700, 650, 600, 550, 750, 650, 850, 800, 700,
        780, 820, 850, 880, 920, 960, 1000, 790
    ],
    "average_co2_production": [
        48745, 8846, 237332, 3820, 15566, 38247, 11384, 9739, 51981, 12248, 42963, 15124, 21607, 20862, 27673, 66527, 3386, 22523, 49978, 46382, 33315, 118387, 15708, 16824, 12051, 44064, 40312,
        75188, 46106, 26387, 56152, 185091, 116967, 144840, 58596, 7907, 57875, 39720, 50162, 67671, 50167, 39443, 42937, 34415, 22120, 23398, 11490,
        55876, 68564, 72342, 78564, 83567, 89564, 95544, 67564
    ],
    "juice_produced": [
        630, 475, 950, 700, 550, 1000, 675, 810, 650, 700, 800, 760, 610, 870, 600, 720, 650, 630, 490, 820, 680, 550, 730, 900, 825, 1000, 630,
        660, 700, 830, 830, 920, 950, 1000, 800, 950, 1050, 960, 875, 825, 750, 725, 850, 820, 1040, 1000, 920,
        880, 940, 1020, 1080, 1150, 1200, 1250, 900
    ]
}

df = pd.DataFrame(data)

df['juice_to_greens'] = df['juice_produced'] / df['Plant_Materials']
df['co2_to_greens'] = df['average_co2_production'] / df['Plant_Materials']
df['log_co2'] = np.log1p(df['average_co2_production'])

X = df[['Plant_Materials', 'juice_produced', 'average_co2_production', 'juice_to_greens', 'co2_to_greens', 'log_co2']]
y = df['Sugar']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=25)

model = GradientBoostingRegressor(n_estimators=100, learning_rate=0.1, random_state=25)
model.fit(X_train, y_train)

joblib.dump(model, 'gbr_model.pkl')

y_pred = model.predict(X_test)
r2 = r2_score(y_test, y_pred)
mse = mean_squared_error(y_test, y_pred)
print(f"\U0001F4CA Model Accuracy (R² Score): {r2:.4f}")
print(f"\U0001F4C9 Mean Squared Error (MSE): {mse:.4f}\n")

juice_to_greens_ratio = df['juice_produced'].mean() / df['Plant_Materials'].mean()
co2_to_greens_ratio = df['average_co2_production'].mean() / df['Plant_Materials'].mean()


def predict_sugar(greens, model):
    greens = np.clip(greens, X_train['Plant_Materials'].min(), X_train['Plant_Materials'].max())

    juice_produced = juice_to_greens_ratio * greens
    average_co2_production = co2_to_greens_ratio * greens

    juice_to_greens = juice_produced / greens if greens != 0 else 0
    co2_to_greens = average_co2_production / greens if greens != 0 else 0
    log_co2 = np.log1p(average_co2_production)

    input_features = pd.DataFrame([[greens, juice_produced, average_co2_production, juice_to_greens, co2_to_greens, log_co2]],
                                  columns=X.columns)
    return model.predict(input_features)[0]


@app.route('/predict_sugar', methods=['POST'])
def predict_sugar_endpoint():
    data = request.json
    greens = float(data['greens'])
    sugar_opt = predict_sugar(greens, model)
    return jsonify({'sugar_opt': sugar_opt})


@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/alerts')
def alerts():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    HUMIDITY_LOW_THRESHOLD = 84
    TEMP_HIGH_THRESHOLD = 35
    TEMP_LOW_THRESHOLD = 32

    alerts = {}
    for container_id in range(1, 4):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        table_name = f"container_{container_id}"
        cursor.execute(f"SELECT Humidity, Temperature FROM {table_name} ORDER BY id DESC LIMIT 1")
        data = cursor.fetchone()
        container_alerts = []

        if data:
            humidity = data.get('Humidity', None)
            temperature = data.get('Temperature', None)

            if humidity is not None and humidity < HUMIDITY_LOW_THRESHOLD:
                container_alerts.append({
                    'title': f'Humidity is low in container {container_id}',
                    'description': f'Humidity is {humidity}%, which is below the threshold of {HUMIDITY_LOW_THRESHOLD}%.'
                })

            if temperature is not None and temperature > TEMP_HIGH_THRESHOLD:
                container_alerts.append({
                    'title': f'Temperature is high in container {container_id}',
                    'description': f'Temperature is {temperature}°C, which is above the threshold of {TEMP_HIGH_THRESHOLD}°C.'
                })

            if temperature is not None and temperature < TEMP_LOW_THRESHOLD:
                container_alerts.append({
                    'title': f'Temperature is low in container {container_id}',
                    'description': f'Temperature is {temperature}°C, which is below the threshold of {TEMP_LOW_THRESHOLD}°C.'
                })

        alerts[container_id] = container_alerts
        conn.close()

    return render_template('alerts.html', alerts=alerts)


@app.route('/api/alerts')
def get_alerts():
    HUMIDITY_LOW_THRESHOLD = 84
    TEMP_HIGH_THRESHOLD = 35
    TEMP_LOW_THRESHOLD = 32


    alerts = {}
    for container_id in range(1, 4):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        table_name = f"container_{container_id}"
        cursor.execute(f"SELECT Humidity, Temperature FROM {table_name} ORDER BY id DESC LIMIT 1")
        data = cursor.fetchone()
        container_alerts = []

        if data:
            humidity = data.get('Humidity', None)
            temperature = data.get('Temperature', None)

            if humidity is not None and humidity < HUMIDITY_LOW_THRESHOLD:
                container_alerts.append({
                    'title': f'Humidity is low in container {container_id}',
                    'description': f'Humidity is {humidity}%, which is below the threshold of {HUMIDITY_LOW_THRESHOLD}%.'
                })

            if temperature is not None and temperature > TEMP_HIGH_THRESHOLD:
                container_alerts.append({
                    'title': f'Temperature is high in container {container_id}',
                    'description': f'Temperature is {temperature}°C, which is above the threshold of {TEMP_HIGH_THRESHOLD}°C.'
                })

            if temperature is not None and temperature < TEMP_LOW_THRESHOLD:
                container_alerts.append({
                    'title': f'Temperature is low in container {container_id}',
                    'description': f'Temperature is {temperature}°C, which is below the threshold of {TEMP_LOW_THRESHOLD}°C.'
                })

        alerts[container_id] = container_alerts
        conn.close()

    return jsonify(alerts)


@app.route('/api/container/<int:container_id>')
def get_container_data(container_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    table_name = f"container_{container_id}"

    query = """
        SELECT Humidity, Temperature, 
               (SELECT start_date FROM fermentation_metadata WHERE container_name = %s) AS start_date,
               (SELECT DATE_ADD(start_date, INTERVAL 7 DAY) FROM fermentation_metadata WHERE container_name = %s) AS min_extraction_date,
               (SELECT Plant_Resource_Amount FROM fermentation_metadata WHERE container_name = %s) AS plant_resource,
               (SELECT Molasses_Amount FROM fermentation_metadata WHERE container_name = %s) AS molasses_amount
        FROM {} ORDER BY id DESC LIMIT 1
    """.format(table_name)

    cursor.execute(query, (table_name, table_name, table_name, table_name))
    data = cursor.fetchone() or {}
    conn.close()

    return jsonify({
        'Humidity': data.get('Humidity', 'N/A'),
        'Temperature': data.get('Temperature', 'N/A'),
        'start_date': data.get('start_date', 'N/A'),
        'min_extraction_date': data.get('min_extraction_date', 'N/A'),
        'plant_resource': data.get('plant_resource', 'N/A'),
        'molasses_amount': data.get('molasses_amount', 'N/A')
    })


@app.route('/container/<int:container_id>')
def container_details(container_id):
    return render_template('container.html', container_id=container_id)


@app.route('/api/carbon-co2-airpressure')
def get_carbon_co2_airpressure():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT carbon_dioxide, air_pressure FROM airpressure_co2 ORDER BY id DESC LIMIT 1")
    data = cursor.fetchone() or {'carbon_dioxide': 'N/A', 'air_pressure': 'N/A'}
    conn.close()
    return jsonify({'CarbonDioxide': data['carbon_dioxide'], 'AirPressure': data['air_pressure']})


@app.route('/api/container/<int:container_id>/begin', methods=['POST'])
def begin_fermentation(container_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json
    plant_resource = data.get('plant_resource')
    molasses_amount = data.get('molasses_amount')
    fermentation_type = data.get('fermentation_type')
    start_date = datetime.now()
    min_extraction_date = start_date + timedelta(days=7)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO fermentation_metadata (container_name, start_date, Plant_Resource_Amount, Molasses_Amount, fermentation_in_progress, fermentation_type)
            VALUES (%s, %s, %s, %s, TRUE, %s)
            ON DUPLICATE KEY UPDATE start_date = VALUES(start_date), Plant_Resource_Amount = VALUES(Plant_Resource_Amount), Molasses_Amount = VALUES(Molasses_Amount), fermentation_in_progress = TRUE, fermentation_type = VALUES(fermentation_type)
        """, (f"container_{container_id}", start_date, plant_resource, molasses_amount, fermentation_type))

        conn.commit()
        return jsonify({
            "success": True,
            "start_date": start_date.strftime("%Y-%m-%d %H:%M:%S"),
            "min_extraction_date": min_extraction_date.strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()


@app.route('/api/container/<int:container_id>/end', methods=['POST'])
def end_fermentation(container_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json
    juice_extracted = data.get("juice_extracted")

    if juice_extracted is None or not isinstance(juice_extracted, (int, float)) or juice_extracted < 0:
        return jsonify({"success": False, "error": "Invalid juice extracted amount"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM fermentation_metadata WHERE container_name = %s", (f"container_{container_id}",))
        fermentation_data = cursor.fetchone()

        if fermentation_data:
            cursor.execute("""
                INSERT INTO previous_trials (container_name, start_date, Plant_Resource_Amount, Molasses_Amount, end_date, fermentation_type1, juice_extracted)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                fermentation_data['container_name'],
                fermentation_data['start_date'],
                fermentation_data['Plant_Resource_Amount'],
                fermentation_data['Molasses_Amount'],
                datetime.now(),
                fermentation_data['fermentation_type'],
                juice_extracted
            ))

            cursor.execute("""
                UPDATE fermentation_metadata
                SET end_date = %s, fermentation_in_progress = FALSE
                WHERE container_name = %s
            """, (datetime.now(), f"container_{container_id}"))

            conn.commit()
            return jsonify({"success": True, "message": "Fermentation Ended!", "juice_extracted": juice_extracted})

        return jsonify({"success": False, "error": "No data found for this container"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()


@app.route('/api/container/<int:container_id>/state')
def get_fermentation_state(container_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fermentation_in_progress, start_date, fermentation_type 
        FROM fermentation_metadata 
        WHERE container_name = %s
    """, (f"container_{container_id}",))

    data = cursor.fetchone()
    conn.close()

    if data:
        return jsonify({
            'fermentation_in_progress': data['fermentation_in_progress'],
            'fermentation_type': data['fermentation_type'],
            'start_date': data['start_date'].strftime("%Y-%m-%d %H:%M:%S") if data['start_date'] else 'N/A',
            'min_extraction_date': (data['start_date'] + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S") if data['start_date'] else 'N/A'
        })
    else:
        return jsonify({
            'fermentation_in_progress': False,
            'fermentation_type': 'N/A',
            'start_date': 'N/A',
            'min_extraction_date': 'N/A'
        })


@app.route('/previous-trials')
def previous_trials():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM previous_trials ORDER BY end_date DESC")
    trials = cursor.fetchall()
    conn.close()

    return render_template('previous_trials.html', trials=trials)


@app.route('/clear-history', methods=['POST'])
def clear_history():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM previous_trials")
    conn.commit()
    conn.close()

    return redirect(url_for('previous_trials'))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)