package sai.service.springsecurityjwt.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthenticateResponse {

	private String jwt;
}
