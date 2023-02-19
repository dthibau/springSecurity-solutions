package org.formation.controller.rest;

import java.util.List;

import javax.persistence.EntityNotFoundException;
import javax.validation.Valid;

import org.formation.model.Client;
import org.formation.model.ClientRepository;
import org.formation.model.Order;
import org.formation.model.OrderItem;
import org.formation.model.OrderRepository;
import org.formation.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

	@Autowired
	OrderService orderService;
	
	@Autowired
	OrderRepository orderRepository;
	
	@Autowired
	ClientRepository clientRepository;
	
	@GetMapping
	List<Order> findAll() {
		return orderRepository.findAll();
	}

	@GetMapping("/client/{clientId}")
	List<Order> findByFournisseur(@PathVariable("clientId") long clientId) {

		Client client = clientRepository.findById(clientId)
				.orElseThrow(() -> new EntityNotFoundException("Client inconnu :" + clientId));
		return orderRepository.findByClient(client);
	}

	@PostMapping
	ResponseEntity<Order> createOrder(@Valid @RequestBody Order order) {
		
		final long clientId = order.getClient().getId();
		Client client = clientRepository.findById(clientId)
				.orElseThrow(() -> new EntityNotFoundException("Client inconnu :" + clientId));
		order.setClient(client);
		for (OrderItem oi : order.getOrderItems() ) {
			oi.setOrder(order);
		}
		order = orderService.processOrder(order);
		
		return new ResponseEntity<Order>(order,HttpStatus.CREATED);
		
	}

}
