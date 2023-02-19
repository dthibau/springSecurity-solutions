package org.formation.model;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PaymentResponse {
	Long requestId;
	Instant instant;
	Boolean outcome;
	String reason;
	
	
	
}
