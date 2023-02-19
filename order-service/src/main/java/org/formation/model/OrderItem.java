package org.formation.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Entity
@Data
public class OrderItem {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	private String refProduct;
	
	private float price;
	
	private int quantity;
	
	@ManyToOne
	@JsonIgnore
	private Order order;
	
	
}
