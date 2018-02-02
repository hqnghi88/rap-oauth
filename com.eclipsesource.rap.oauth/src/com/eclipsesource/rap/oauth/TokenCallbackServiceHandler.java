
package com.eclipsesource.rap.oauth;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.rap.rwt.RWT;
import org.eclipse.rap.rwt.service.ServiceHandler;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.CredentialRefreshListener;
import com.google.api.client.auth.oauth2.TokenErrorResponse;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.Drive.Files;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.Person;

public class TokenCallbackServiceHandler implements ServiceHandler {

	private static final HttpTransport TRANSPORT = new NetHttpTransport();
	private static final JacksonFactory JSON_FACTORY = new JacksonFactory();

	private final GoogleClientSecrets clientSecrets = Authorization.clientSecrets;

	public TokenCallbackServiceHandler() {

	}

	@Override
	public void service(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		System.out.println("current HTTP session: " + request.getSession().getId());
		System.out.println("current UI session: " + RWT.getUISession().getId());
		if (request.getMethod() == "POST") {
			System.out.println("received POST");
			JsonParser parser = JSON_FACTORY.createJsonParser(request.getInputStream());
			System.out.println(parser.parseAndClose(TokenResponse.class));
			// TODO handle POST request containing a complete TokenResponse as JSON

		} else if (request.getMethod() == "GET") {
			System.out.println("received GET");
			PrintWriter out = new PrintWriter(response.getOutputStream());
			String token = request.getParameter("token");
			if (token != null && !token.equals("undefined")) {
				System.out.println("token=" + token);
				handleIdToken(request.getParameter("idToken"));
				handleToken(token);
				out.println("callback Token OK");
			} else {
				out.println("callback ERROR (no token)");
			}
			String code = request.getParameter("code");
			if (code != null && !code.isEmpty() && !code.equals("undefined")) {
				System.out.println("code=" + code);
				handleCode(code);
				out.println("callback Code OK");
			} else {
				out.println("callback ERROR (no code)");
			}
			out.flush();
		} else {
			response.setStatus(501);
		}
	}

	private void handleCode(String code) {
		try {
			String clientId = clientSecrets.getWeb().getClientId();
			String clientSecret = clientSecrets.getWeb().getClientSecret();
			GoogleTokenResponse tokenResponse = new GoogleAuthorizationCodeTokenRequest(TRANSPORT, JSON_FACTORY,
					clientId, clientSecret, code, "postmessage").execute();
			System.out.println("exchanged code for access token: " + tokenResponse.getAccessToken());
			System.out.println("refresh token: " + tokenResponse.getRefreshToken());
			System.out.println("token response expires in " + tokenResponse.getExpiresInSeconds() + "s");

			// Create a credential representation of the token data.
			GoogleCredential credential = new GoogleCredential.Builder().setJsonFactory(JSON_FACTORY)
					.setTransport(TRANSPORT).setClientSecrets(clientId, clientSecret)
					.addRefreshListener(new CredentialRefreshListener() {

						@Override
						public void onTokenResponse(Credential credential, TokenResponse tokenResponse)
								throws IOException {
							System.out.println("RefreshListener: token response");
						}

						@Override
						public void onTokenErrorResponse(Credential credential, TokenErrorResponse tokenErrorResponse)
								throws IOException {
							System.out.println("RefreshListener: token response");
						}
					}).build().setFromTokenResponse(tokenResponse);
			System.out.println("created credentials from access token: " + credential.getAccessToken());
			System.out.println("credentials' refresh token: " + credential.getRefreshToken());
			System.out.println("credentials expire in " + credential.getExpiresInSeconds() + "s");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

    private static final List<String> SCOPES =
        Arrays.asList(DriveScopes.DRIVE_APPDATA);

    private static final java.io.File DATA_STORE_DIR = new java.io.File(
        System.getProperty("user.home"), "./credentials/drive-java-quickstart");

    private static FileDataStoreFactory DATA_STORE_FACTORY;

	/*
	 * 2014-02-05 I guess, using the token on the server will only work as long as I
	 * am working on localhost (browser AND server!) When using a real server the
	 * token should be rejected by the server. Instead we have to use the "code" to
	 * get our own token on the server! See:
	 * https://developers.google.com/+/web/signin/server-side-flow
	 */
	private void handleToken(String token) {
		TokenResponse tokenResponse = new TokenResponse();
		tokenResponse.setAccessToken(token);
		tokenResponse.setTokenType("bearer");
		tokenResponse.setScope(DriveScopes.DRIVE_FILE);
		GoogleCredential credential = new GoogleCredential.Builder().setJsonFactory(JSON_FACTORY)
			.setTransport(TRANSPORT).setClientSecrets(clientSecrets).build().setFromTokenResponse(tokenResponse);
//		Plus plus = new Plus.Builder(TRANSPORT, JSON_FACTORY, credential).setApplicationName("RAP OAuth Demo").build();
        try {
//			DATA_STORE_FACTORY = new FileDataStoreFactory(DATA_STORE_DIR);
//
//		GoogleAuthorizationCodeFlow flow =
//                new GoogleAuthorizationCodeFlow.Builder(
//                        TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
//                .setDataStoreFactory(DATA_STORE_FACTORY)
//                .setAccessType("offline")
//                .build();
//		Credential credential = new AuthorizationCodeInstalledApp(
//            flow, new LocalServerReceiver()).authorize("user");
//        System.out.println(
//                "Credentials saved to " + DATA_STORE_DIR.getAbsolutePath());

//			Person mePerson = plus.people().get("me").execute();
//			System.out.println(mePerson.getDisplayName());

			// String accessToken = tokenResponse.getAccessToken();
//			GoogleCredential ccredential = credential.createScoped(Arrays.asList(DriveScopes.DRIVE_FILE));

			// Use access token to call API
			Drive drive = new Drive.Builder(TRANSPORT, JSON_FACTORY, credential)
					.setApplicationName("GAMA Cloud").build();
			FileList files = drive.files().list()
				    .setSpaces("drive")
				    .execute();
				for (File file : files.getItems()) {
				  System.out.printf("Found file: %s %s \n",
				      file.getTitle(),file.getMimeType() );
				}

//			File file = drive.files().get("appfolder").execute();
//			List<File> f=retrieveAllFiles(drive);
//			System.out.println("   " + f.size());

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static List<File> retrieveAllFiles(Drive service) throws IOException {
		List<File> result = new ArrayList<File>();
		Files.List request = service.files().list();

		do {
			try {
				FileList files = request.execute();

				result.addAll(files.getItems());
				request.setPageToken(files.getNextPageToken());
			} catch (Exception e) {
				e.printStackTrace();
				request.setPageToken(null);
			}
		} while (request.getPageToken() != null && request.getPageToken().length() > 0);

		return result;
	}

	private void handleIdToken(String idTokenString) {
		System.out.println("idToken=" + idTokenString);
		GoogleIdToken idToken = null;
		JacksonFactory jsonFactory = new JacksonFactory();
		try {
			idToken = GoogleIdToken.parse(jsonFactory, idTokenString);
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier(new NetHttpTransport(), jsonFactory);
			System.out.println("idToken is valid: " + verifier.verify(idToken));
			System.out.println("Google+ ID: " + idToken.getPayload().getSubject());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}
}
