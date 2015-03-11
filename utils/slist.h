// strings linked list item structure
typedef struct slist_item {
	char *value;
	struct slist_item *next;
} slist_item;

// strings linked list
typedef struct slist{
	slist_item *head;
	slist_item *last;
	int size;
} slist;

void slist_append(slist *list, char* value);
void slist_free(slist *list);
void slist_iter(slist *list, void (*f)(const char* item));
int slist_all(slist *list, int (*f)(char* item));
int slist_any(slist *list, int (*f)(char* item));
int slist_any_str(slist *list, const char *needle);
void slist_print_item(const char* item);
