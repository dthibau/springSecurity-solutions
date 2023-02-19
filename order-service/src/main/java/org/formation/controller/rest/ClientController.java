package org.formation.controller.rest;

import java.util.List;

import javax.persistence.EntityNotFoundException;
import javax.validation.Valid;

import org.formation.model.Client;
import org.formation.model.ClientRepository;
import org.formation.model.Order;
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
@RequestMapping("/api/clients")
public class ClientController {

	
	@Autowired
	ClientRepository clientRepository;
	
	@GetMapping
	List<Client> findAll() {
		return clientRepository.findAll();
	}


}
