insert into fournisseur (nom,reference) values ('Belleville express','BELLE')
insert into fournisseur (nom,reference) values ('BricBrac Import/Export','BRICB')
insert into fournisseur (nom,reference) values ('Luxuary unlimited','LUXUA')

insert into produit (availability,description,hauteur,largeur, longueur,nom,prix_unitaire,reference,fournisseur_id) values (1, 'bla-bla', 150, 210, 300, 'Lit Tania', 359, 'TAN78', 1);
insert into produit (availability,description,hauteur,largeur, longueur,nom,prix_unitaire,reference,fournisseur_id) values (1, 'bli-bli', 150, 210, 300, 'Stuva Fritids', 92.0, 'STU92', 2);
insert into produit (availability,description,hauteur,largeur, longueur,nom,prix_unitaire,reference,fournisseur_id) values (1, 'bli-bli', 150, 210, 300, 'Godishus', 79.95, 'GOD79', 2);

-- Rôles
insert into role (name) values ('ROLE_PRODUCT_MANAGER');
insert into role (name) values ('ROLE_MANAGER');

-- Mot de passe BCrypt 'secret'
insert into member (created, disabled, email, first_name, last_name, login , password,role_id) values ('2019-05-01', null, 'pmanager@grocery.com', 'Mr', 'ProductManager', 'pmanager', '$2a$10$aK81fm.BSg13nxvjEKcEfeD/3cCphRLVCHiQgyhvX1tHYLkH309RC',1);
insert into member (created, disabled, email, first_name, last_name, login , password,role_id) values ('2019-05-01', null, 'manager@grocery.com', 'Mr', 'Manager', 'manager', '$2a$10$aK81fm.BSg13nxvjEKcEfeD/3cCphRLVCHiQgyhvX1tHYLkH309RC',2);




