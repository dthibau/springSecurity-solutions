package org.formation.model;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import lombok.Data;

@Data
@Entity
public class Member {
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	String login,email,password;
	
	@Temporal(TemporalType.DATE)
	Date created, disabled;
	
	String firstName, lastName;
	
	@ManyToOne
	private Role role;
}
