package org.formation.service;

import org.formation.model.Order;
import org.formation.model.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import lombok.extern.java.Log;

@Service
@Log
public class OrderService {

	public static String ORDER_PENDING = "PENDING";
	public static String ORDER_CANCELED = "CANCELED";
	public static String ORDER_CONFIRMED = "CONFIRMED";




	@Autowired
	private OrderRepository orderRepository;





	public Order processOrder(Order order) {


		Order ret = orderRepository.save(order);


		return ret;
	}





}
