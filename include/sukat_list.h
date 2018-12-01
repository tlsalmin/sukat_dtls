#pragma once

/** @brief List appended to start of data. */
typedef struct sukat_list_link
{
  struct sukat_list_link *prev; //!< Link to next.
  struct sukat_list_link *next; //!< Link to next.
} sukat_list_link_t;

/** @brief List head. Initialize to NULLs */
typedef struct sukat_list
{
  sukat_list_link_t *head; //!< Head.
  sukat_list_link_t *tail; //!< Tail.
} sukat_list_t;

/**
 * @brief Add to tail of list.
 */
void sukat_list_add_to_tail(sukat_list_t *list, sukat_list_link_t *link);

/**
 * @brief Remove from list.
 */
void sukat_list_remove(sukat_list_t *list, sukat_list_link_t *link);

/**
 * @brief Begin iterating list.
 */
sukat_list_link_t *sukat_list_begin(sukat_list_t *list);

/**
 * @brief Get next of link 
 */
sukat_list_link_t *sukat_list_next(sukat_list_link_t *link);

/**
 * @brief Return the contained element in the link.
 *
 * @param _link Pointer to the link element.
 * @param _struct_name  Name of original structure to include.
 * @param _member_name  Name of link in \p _struct_name content
 *
 * @return Pointer to start of \p _struct_name
 */
#define sukat_list_data(_link, _struct_name, _member_name)                     \
  (_struct_name *)(_link + offsetof(_struct_name, _member_name))
