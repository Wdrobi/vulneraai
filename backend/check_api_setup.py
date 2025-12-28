"""
VulneraAI - API Configuration Helper
Run this script to check your API setup and test connectivity
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_api_setup():
    """Check which APIs are configured"""
    
    print("=" * 60)
    print("VulneraAI - API Configuration Status")
    print("=" * 60)
    print()
    
    # Check Censys
    censys_id = os.environ.get('CENSYS_API_ID', '')
    censys_secret = os.environ.get('CENSYS_API_SECRET', '')
    
    if censys_id and censys_secret:
        print("✅ Censys API: CONFIGURED")
        print(f"   API ID: {censys_id[:8]}..." if len(censys_id) > 8 else f"   API ID: {censys_id}")
    else:
        print("❌ Censys API: NOT CONFIGURED")
        print("   Get your API key at: https://search.censys.io/account/api")
    print()
    
    # Check NVD
    nvd_key = os.environ.get('NVD_API_KEY', '')
    
    if nvd_key:
        print("✅ NVD API: CONFIGURED")
        print(f"   API Key: {nvd_key[:8]}..." if len(nvd_key) > 8 else f"   API Key: {nvd_key}")
    else:
        print("❌ NVD API: NOT CONFIGURED")
        print("   Get your API key at: https://nvd.nist.gov/developers/request-an-api-key")
    print()
    
    # Check VirusTotal
    vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    if vt_key:
        print("✅ VirusTotal API: CONFIGURED")
        print(f"   API Key: {vt_key[:8]}..." if len(vt_key) > 8 else f"   API Key: {vt_key}")
    else:
        print("❌ VirusTotal API: NOT CONFIGURED")
        print("   Get your API key at: https://www.virustotal.com/gui/my-apikey")
    print()
    
    # Summary
    configured = sum([
        bool(censys_id and censys_secret),
        bool(nvd_key),
        bool(vt_key)
    ])
    
    print("=" * 60)
    print(f"Status: {configured}/3 APIs configured")
    print("=" * 60)
    print()
    
    if configured == 0:
        print("⚠️  No APIs configured. Scanner will work with basic features only.")
        print("📖 See API_SETUP_GUIDE.md for setup instructions.")
    elif configured < 3:
        print("⚠️  Some APIs not configured. Configure all APIs for best results.")
        print("📖 See API_SETUP_GUIDE.md for setup instructions.")
    else:
        print("🎉 All APIs configured! Your scanner is fully powered.")
        print("🚀 Ready to perform comprehensive security scans!")
    
    print()

def test_api_connectivity():
    """Test API connectivity (optional)"""
    print("=" * 60)
    print("Testing API Connectivity")
    print("=" * 60)
    print()
    
    try:
        from services.api_integrations import APIIntegrations
        api = APIIntegrations()
        
        # Test VirusTotal (most reliable test target)
        vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        if vt_key:
            print("Testing VirusTotal API...")
            result = api.virustotal_scan_ip('8.8.8.8')
            if result:
                print("✅ VirusTotal API: WORKING")
            else:
                print("❌ VirusTotal API: FAILED (check API key)")
        
        print()
        print("Note: Full API tests require actual scans to verify all endpoints.")
        
    except Exception as e:
        print(f"❌ Error testing APIs: {str(e)}")
    
    print()

if __name__ == '__main__':
    check_api_setup()
    
    # Uncomment to test connectivity (will make API calls)
    # test_api_connectivity()
    
    print("💡 Tip: Copy .env.example to .env and add your API keys!")
    print()
