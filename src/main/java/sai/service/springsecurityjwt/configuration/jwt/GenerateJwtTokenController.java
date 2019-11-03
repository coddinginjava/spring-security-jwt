package sai.service.springsecurityjwt.configuration.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import sai.service.springsecurityjwt.configuration.MyUserDetailsService;
import sai.service.springsecurityjwt.model.AuthenticateRequest;
import sai.service.springsecurityjwt.model.AuthenticateResponse;

@RestController
public class GenerateJwtTokenController {
	

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;
	
	
	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticateResponse> createAuthenticationToke(
			@RequestBody AuthenticateRequest authenticateRequest) throws Exception {

		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticateRequest.getUserName(), authenticateRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrect username or password " + e);
		}

		UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticateRequest.getUserName());

		String jwt = jwtUtil.generateToken(userDetails);

		return ResponseEntity.ok(new AuthenticateResponse(jwt));

	}

	
}
