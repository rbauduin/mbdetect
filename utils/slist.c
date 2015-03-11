#include <stdlib.h>
#include <ares.h>
#include <string.h>
#include "slist.h"
#include <stdio.h>


// initialise linked list
void slist_init(slist **list) {
	*list = (slist *) malloc(sizeof(slist));
	(*list)->head = NULL;
	(*list)->last = (*list)->head;
	(*list)->size = 0;
}

// append one item to the linked list
void slist_append(slist *list, char* value) {
	if (list->size==0) {
		list->head = (slist_item*) malloc(sizeof(slist_item));
		list->last = list->head;
		list->size++;
	}
	else {
		list->last->next = (slist_item*) malloc(sizeof(slist_item));
		list->last = list->last->next;
		list->size++;
	}
	list->last->value = (char *) malloc(INET6_ADDRSTRLEN);
	list->last->next = NULL;
	strncpy(list->last->value, value,  INET6_ADDRSTRLEN);

}


// free items of the linked list
void slist_free(slist *list) {
	slist_item *head = list->head, *previous=NULL;
	while (head!=NULL){
		free(head->value);
		previous=head;
		head = head->next;
		free(previous);
	}
}

// apply f on all list items's string in turn
void slist_iter(slist *list, void (*f)(const char* item)){
	slist_item *head = list->head;
	while (head!=NULL){
		f(head->value);
		head = head->next;
	}
}

// return 1 if all applications of f on items in list return 1, 0 otherwise
int slist_all(slist *list, int (*f)(char* item)){
	slist_item *head = list->head;
	while (head!=NULL){
		if (f(head->value)) {
			head = head->next;
		}
		else {
			return 0;
		}
	}
	return 1;
}

// return 1 if any application of f on items in list return 1, 0 if all return 0
int slist_any(slist *list, int (*f)(char* item)){
	slist_item *head = list->head;
	while (head!=NULL){
		if (f(head->value)) {
			return 1;
		}
		else {
			head = head->next;
		}
	}
	return 0;
}

// returns one if needle is found in list
int slist_any_str(slist *list, const char *needle){
	slist_item *head = list->head;
	while (head!=NULL){
		if (!strcmp(needle, head->value)) {
			return 1;
		}
		else {
			head = head->next;
		}
	}
	return 0;
}


// function to print each string in list in combination with slist_iter
void slist_print_item(const char* item) {
	printf("list item: %s\n", item);

}


