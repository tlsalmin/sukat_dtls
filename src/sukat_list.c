#include <assert.h>
#include <stdlib.h>
#include "sukat_list.h"

void sukat_list_add_to_tail(sukat_list_t *list, sukat_list_link_t *link)
{
  if (list)
    {
      link->next = link->prev = NULL;
      if (!list->head)
        {
          list->head = list->tail = link;
        }
      else
        {
          assert(list->tail);
          list->tail->next = link;
          link->prev = list->tail;
          list->tail = link;
        }
    }
}

void sukat_list_remove(sukat_list_t *list, sukat_list_link_t *link)
{
  if (list)
    {
      if (list->head == link)
        {
          list->head = link->next;
          if (link->next)
            {
              link->next->prev = NULL;
            }
        }
      else if (list->tail == link)
        {
          assert(link->prev);
          list->tail = link->prev;
          link->prev->next = NULL;
        }
      else
        {
          link->prev->next = link->next;
          link->next->prev = link->prev;
        }
      link->next = link->prev = NULL;
    }
}

sukat_list_link_t *sukat_list_begin(sukat_list_t *list)
{
  if (list)
    {
      return list->head;
    }
  return NULL;
}

sukat_list_link_t *sukat_list_next(sukat_list_link_t *link)
{
  return link->next;
}
