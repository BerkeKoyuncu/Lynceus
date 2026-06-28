import os
import sys
import unittest
from werkzeug.security import generate_password_hash
import pyotp

# Add root folder to path so we can import app and models
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User

class Test2FAEnforcement(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        # Use an in-memory SQLite database for clean testing or use the existing DB context.
        # Since we want to ensure it works, let's configure an in-memory DB or a temp DB.
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        
        self.client = app.test_client()
        
        # Create standard user
        self.email = "testadmin@example.com"
        self.password = "Secr3tP@ssw0rd!"
        self.user = User(
            email=self.email,
            password_hash=generate_password_hash(self.password),
            is_admin=False
        )
        db.session.add(self.user)
        
        # Create a primary admin who can promote users
        self.primary_admin = User(
            email="primary@example.com",
            password_hash=generate_password_hash("adminpass"),
            is_admin=True,
            otp_secret=pyotp.random_base32()
        )
        db.session.add(self.primary_admin)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_complete_2fa_flow(self):
        print("\n--- STEP 1: Log in standard user before promotion ---")
        # Log in standard user - should bypass 2FA and log in directly
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, follow_redirects=True)
        self.assertIn(b'Login successful.', response.data)
        self.assertIn(b'Dashboard', response.data)
        
        # Log out
        self.client.get('/logout', follow_redirects=True)

        print("--- STEP 2: Promote standard user to Admin ---")
        # First login as primary admin
        self.client.post('/login', data={
            'email': 'primary@example.com',
            'password': 'adminpass'
        }, follow_redirects=False)
        # Note: Since primary admin has OTP secret, they redirect to 2FA page.
        # We need to verify 2FA for primary admin first
        with self.client.session_transaction() as sess:
            pre_2fa_id = sess.get('pre_2fa_user_id')
            self.assertEqual(pre_2fa_id, self.primary_admin.id)
        
        # Submit valid OTP for primary admin
        totp = pyotp.TOTP(self.primary_admin.otp_secret)
        otp_code = totp.now()
        response = self.client.post('/login/2fa', data={'otp_code': otp_code}, follow_redirects=True)
        self.assertIn(b'Login successful.', response.data)

        # Toggle role of the standard user to admin
        response = self.client.post(f'/admin/user/{self.user.id}/toggle-admin', follow_redirects=True)
        self.assertIn(b"Role of user testadmin@example.com updated to", response.data)
        self.assertIn(b"Admin", response.data)
        
        # Verify database state
        db_user = db.session.get(User, self.user.id)
        self.assertTrue(db_user.is_admin)
        self.assertIsNone(db_user.otp_secret)
        print("Successfully verified: User is admin and has no OTP secret set.")

        # Log out primary admin
        self.client.get('/logout', follow_redirects=True)

        print("--- STEP 3: Log in as newly promoted Admin (Should redirect to setup) ---")
        # Attempt to login as testadmin
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login/2fa-setup'))
        
        # Verify session holds temporary secret and user ID
        with self.client.session_transaction() as sess:
            setup_secret = sess.get('setup_2fa_secret')
            setup_id = sess.get('setup_2fa_user_id')
            self.assertIsNotNone(setup_secret)
            self.assertEqual(setup_id, self.user.id)
            print(f"Temporary setup secret generated in session: {setup_secret}")

        print("--- STEP 4: Access 2FA Setup GET endpoint ---")
        response = self.client.get('/login/2fa-setup')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Set Up 2-Factor Authentication', response.data)
        self.assertIn(setup_secret.encode(), response.data)
        self.assertIn(b'api.qrserver.com', response.data)

        print("--- STEP 5: Submit invalid OTP code to setup ---")
        response = self.client.post('/login/2fa-setup', data={'otp_code': '000000'}, follow_redirects=True)
        self.assertIn(b'Invalid verification code. Please try again.', response.data)
        
        # Verify DB still has no otp_secret
        db_user = db.session.get(User, self.user.id)
        self.assertIsNone(db_user.otp_secret)

        print("--- STEP 6: Submit VALID OTP code to setup ---")
        setup_totp = pyotp.TOTP(setup_secret)
        valid_otp = setup_totp.now()
        response = self.client.post('/login/2fa-setup', data={'otp_code': valid_otp}, follow_redirects=True)
        self.assertIn(b'2FA configured and login successful.', response.data)
        self.assertIn(b'Dashboard', response.data)

        # Verify DB now has the correct otp_secret stored and session cleared
        db_user = db.session.get(User, self.user.id)
        self.assertEqual(db_user.otp_secret, setup_secret)
        
        with self.client.session_transaction() as sess:
            self.assertNotIn('setup_2fa_secret', sess)
            self.assertNotIn('setup_2fa_user_id', sess)
        print("OTP secret committed to database and session cleared successfully.")

        # Log out
        self.client.get('/logout', follow_redirects=True)

        print("--- STEP 6.5: Reset 2FA of testadmin by primary admin ---")
        # Log in as primary admin again
        self.client.post('/login', data={
            'email': 'primary@example.com',
            'password': 'adminpass'
        }, follow_redirects=False)
        self.client.post('/login/2fa', data={'otp_code': pyotp.TOTP(self.primary_admin.otp_secret).now()}, follow_redirects=True)
        
        # Reset 2FA of testadmin
        response = self.client.post(f'/admin/user/{self.user.id}/reset-2fa', follow_redirects=True)
        self.assertIn(b"Two-Factor Authentication (2FA) has been reset for testadmin@example.com.", response.data)
        
        # Verify DB state: testadmin is still admin but otp_secret is None
        db_user = db.session.get(User, self.user.id)
        self.assertTrue(db_user.is_admin)
        self.assertIsNone(db_user.otp_secret)
        print("Successfully verified: 2FA reset cleared otp_secret but retained admin role.")
        
        # Set up 2FA for testadmin again so subsequent steps of the test can continue
        # Log out primary admin
        self.client.get('/logout', follow_redirects=True)
        
        # Login as testadmin again - should redirect to setup
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login/2fa-setup'))
        
        with self.client.session_transaction() as sess:
            new_setup_secret = sess.get('setup_2fa_secret')
        
        # Complete setup
        self.client.post('/login/2fa-setup', data={'otp_code': pyotp.TOTP(new_setup_secret).now()}, follow_redirects=True)
        db_user = db.session.get(User, self.user.id) # refresh
        
        # Log out
        self.client.get('/logout', follow_redirects=True)

        print("--- STEP 7: Subsequent Login (Should redirect to standard 2FA verification) ---")
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login/2fa'))

        # Verify invalid code on regular 2FA
        response = self.client.post('/login/2fa', data={'otp_code': '999999'}, follow_redirects=True)
        self.assertIn(b'Invalid verification code. Please try again.', response.data)

        # Verify valid code on regular 2FA
        user_totp = pyotp.TOTP(db_user.otp_secret)
        response = self.client.post('/login/2fa', data={'otp_code': user_totp.now()}, follow_redirects=True)
        self.assertIn(b'Login successful.', response.data)

        # Log out
        self.client.get('/logout', follow_redirects=True)

        print("--- STEP 8: Demote Admin and verify 2FA is removed ---")
        # Log in as primary admin again to demote
        self.client.post('/login', data={
            'email': 'primary@example.com',
            'password': 'adminpass'
        }, follow_redirects=False)
        self.client.post('/login/2fa', data={'otp_code': pyotp.TOTP(self.primary_admin.otp_secret).now()}, follow_redirects=True)
        
        # Demote user
        response = self.client.post(f'/admin/user/{self.user.id}/toggle-admin', follow_redirects=True)
        self.assertIn(b"Role of user testadmin@example.com updated to", response.data)
        self.assertIn(b"User", response.data)

        # Verify DB state: is_admin=False, otp_secret=None
        db_user = db.session.get(User, self.user.id)
        self.assertFalse(db_user.is_admin)
        self.assertIsNone(db_user.otp_secret)
        print("Successfully verified: Demoted user has no admin role and otp_secret is cleared.")

        # Log out primary admin
        self.client.get('/logout', follow_redirects=True)

        # Attempt to log in as the demoted user (standard user) - should login directly
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, follow_redirects=True)
        self.assertIn(b'Login successful.', response.data)
        self.assertNotIn('2fa', response.request.path)
        print("Success! Demoted user logged in directly without 2FA.")

class TestTargetSafetyValidation(unittest.TestCase):
    def test_comma_separated_target_safety(self):
        from scanner import calculate_network, validate_scan_target
        
        # 1. Private and loopback comma list - should be valid
        res = calculate_network("192.168.1.10,127.0.0.1,192.168.1.20")
        self.assertTrue(res["success"])
        val_res = validate_scan_target(res, "fast")
        self.assertTrue(val_res["success"])
        
        # 2. Comma list containing public IP in the middle - should be invalid
        res = calculate_network("192.168.1.10,8.8.8.8,192.168.1.20")
        self.assertTrue(res["success"])
        val_res = validate_scan_target(res, "fast")
        self.assertFalse(val_res["success"])
        self.assertEqual(val_res["error"], "Only private, loopback, or link-local networks are allowed to be scanned.")
        
        # 3. Comma list containing public IP at first position - should be invalid
        res = calculate_network("8.8.8.8,192.168.1.10")
        self.assertTrue(res["success"])
        val_res = validate_scan_target(res, "fast")
        self.assertFalse(val_res["success"])
        
        # 4. Comma list containing public IP at last position - should be invalid
        res = calculate_network("192.168.1.10,8.8.8.8")
        self.assertTrue(res["success"])
        val_res = validate_scan_target(res, "fast")
        self.assertFalse(val_res["success"])

if __name__ == '__main__':
    unittest.main()
