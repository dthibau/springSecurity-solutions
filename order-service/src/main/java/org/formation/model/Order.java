package org.formation.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;

import lombok.Data;

@Entity
@Table(name = "t_order")
@Data
public class Order {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	private Instant date;
	
	private float discount;
	
	private String status;
	
	@ManyToOne
	private Client client;
	
	@OneToMany(cascade = CascadeType.ALL, mappedBy = "order")
	List<OrderItem> orderItems = new ArrayList<>();
	
	
	@Transient
	public Float getAmount() {
		float total = orderItems.stream().map(oi -> oi.getQuantity()*oi.getPrice()).reduce(0f,(a,b) -> a+b);
		return total-total*discount;
		
	}
}
