"""
Test script to verify all components are working correctly
Run this before deploying to production
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_database():
    """Test database initialization"""
    print("Testing Database Manager...")
    try:
        from db_manager import DatabaseManager
        db = DatabaseManager()
        print(f"[OK] Database initialized: {db.db_type}")
        
        # Test connection
        with db.get_connection() as conn:
            cursor = conn.cursor()
            if db.db_type == 'postgresql':
                cursor.execute('SELECT 1')
            else:
                cursor.execute('SELECT 1')
            result = cursor.fetchone()
            print(f"[OK] Database connection test: PASSED")
        
        # Test table creation
        db.init_tables()
        print("[OK] Database tables initialized")
        return True
    except Exception as e:
        print(f"❌ Database test failed: {str(e)}")
        return False

def test_rate_limiter():
    """Test rate limiter"""
    print("\nTesting Rate Limiter...")
    try:
        from rate_limiter import rate_limiter
        is_allowed, remaining = rate_limiter.is_allowed("test:127.0.0.1", "api")
        print(f"[OK] Rate limiter initialized")
        print(f"   Test request: allowed={is_allowed}, remaining={remaining}")
        return True
    except Exception as e:
        print(f"❌ Rate limiter test failed: {str(e)}")
        return False

def test_docker_manager():
    """Test Docker manager"""
    print("\nTesting Docker Manager...")
    try:
        from docker_manager import DockerManager
        docker_mgr = DockerManager()
        docker_mgr.client.ping()
        print("[OK] Docker connection: PASSED")
        return True
    except Exception as e:
        print(f"⚠️  Docker test failed (this is OK if Docker is not running): {str(e)}")
        return False

def test_imports():
    """Test all imports"""
    print("\nTesting Imports...")
    try:
        from flask import Flask
        from flask_cors import CORS
        import docker
        import psycopg2
        print("[OK] All required packages imported successfully")
        return True
    except ImportError as e:
        print(f"⚠️  Missing package (may be OK for development): {str(e)}")
        print("   Install with: pip install -r requirements.txt")
        return False

def test_environment():
    """Test environment variables"""
    print("\nTesting Environment Variables...")
    db_type = os.getenv('DATABASE_TYPE', 'sqlite')
    print(f"   DATABASE_TYPE: {db_type}")
    
    if db_type == 'postgresql':
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            print(f"   DATABASE_URL: {'*' * 20} (hidden)")
        else:
            print("   ⚠️  DATABASE_URL not set (will use SQLite)")
    
    flask_key = os.getenv('FLASK_SECRET_KEY')
    if flask_key and flask_key != 'change_this_secret_key_in_production':
        print("   FLASK_SECRET_KEY: [OK] Set")
    else:
        print("   [WARN] FLASK_SECRET_KEY: Using default (change in production!)")
    
    return True

def main():
    """Run all tests"""
    print("=" * 60)
    print("Deployment Platform - Setup Verification")
    print("=" * 60)
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Environment", test_environment()))
    results.append(("Database", test_database()))
    results.append(("Rate Limiter", test_rate_limiter()))
    results.append(("Docker", test_docker_manager()))
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{name:20} {status}")
    
    all_passed = all(result for _, result in results)
    
    if all_passed:
        print("\n[SUCCESS] All critical tests passed!")
        print("   You're ready to deploy.")
    else:
        print("\n[WARNING] Some tests failed or have warnings.")
        print("   Review the output above and fix any issues.")
    
    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())

