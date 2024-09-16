package org.formation.model;

import java.util.Date;


import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class Member {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	String login,email,password;
	
	@Temporal(TemporalType.DATE)
	Date created, disabled;
	
	String firstName, lastName;
	
	@ManyToOne
	private Role role;
}
