from django.shortcuts import render, redirect
import os
import json
from django.urls import reverse
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from django.shortcuts import redirect
from django.http import HttpResponse
from django.conf import settings
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow


# Google OAuth2 client ID and secret
CLIENT_SECRETS_FILE = os.path.join(settings.BASE_DIR, 'credentials.json')
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

REDIRECT_URI = 'http://localhost:8000/google/callback/'


def home(request):
    return render(request,'home.html')

def google_login(request): #to login into google first we need to add the email as test user in google concent screen   for development purpose
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = REDIRECT_URI

    # Add include_granted_scopes to handle the verification issue
    authorization_url, state = flow.authorization_url(
        access_type='offline', 
        prompt='consent',
        include_granted_scopes='true'
    )

    # Store the state in the session for later use
    request.session['state'] = state

    return redirect(authorization_url)


def google_callback(request):
    """
    Handle OAuth callback from Google.
    Save credentials and redirect to email fetching.
    """
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        flow.fetch_token(authorization_response=request.build_absolute_uri())

        credentials = flow.credentials
        
        # Save credentials for future use
        with open('token.json', 'w') as token:
            token.write(credentials.to_json())
        
        # Redirect to email fetching page
        return redirect('fetch_emails')
    
    except Exception as e:
        error_message = f"""
        <h2>OAuth Error</h2>
        <p><strong>Error:</strong> {str(e)}</p>
        <h3>Possible Solutions:</h3>
        <ul>
            <li>Make sure you're added as a test user in Google Cloud Console</li>
            <li>Check that your credentials.json file is properly configured</li>
            <li>Ensure your OAuth consent screen is set to "Testing" mode</li>
        </ul>
        <p><a href="/google/login/">Try Again</a> | <a href="/">Go Home</a></p>
        """
        return HttpResponse(error_message)




def fetch_emails(request):
    """
    Main function to fetch and display emails.
    This function handles both fresh authentication and stored credentials.
    """
    try:
        # Try to load stored credentials
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)

        if not creds or not creds.valid:
            # If no valid credentials, redirect to login
            return HttpResponse("""
                <h2>No Valid Credentials</h2>
                <p>You need to authenticate first.</p>
                <a href="/google/login/">Login with Google</a> | 
                <a href="/">Go Home</a>
            """)
        
        # Build Gmail service with stored credentials
        service = build('gmail', 'v1', credentials=creds)

        # Fetch messages
        result = service.users().messages().list(userId='me', maxResults=5).execute()
        messages = result.get('messages', [])

        # Process emails
        email_data = []
        for msg in messages:
            msg_detail = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_detail['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            snippet = msg_detail.get('snippet', '')
            email_data.append({
                'subject': subject,
                'sender': sender,
                'snippet': snippet,
            })
        
        return render(request, 'emails.html', {'emails': email_data})
        
    except Exception as e:
        return HttpResponse(f"""
            <h2>Error Fetching Emails</h2>
            <p><strong>Error:</strong> {str(e)}</p>
            <p><a href="/google/login/">Re-authenticate</a> | <a href="/">Go Home</a></p>
        """)