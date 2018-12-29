/*	--*- c -*--
 * Copyright (C) 2013 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_ENSC_LIB_LIST_H
#define H_ENSC_LIB_LIST_H

#ifdef NDEBUG
#  undef DEBUG_LIST
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef DEBUG_LIST
#  include <assert.h>
#  include "abort.h"
#endif

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

/*@{*/

/*! \brief List datastructure
 *
 *  Must be initialized by list_init() before usage */
struct list_head {
	struct list_head	*next;
	struct list_head	*prev;
};

#define LIST_POISON0	((struct list_head *)(0xddcc0011))
#define LIST_POISON1	((struct list_head *)(0xddcc1111))

inline static void list_validate(struct list_head const *head)
{
#ifdef DEBUG_LIST
	struct list_head const		*i;
	struct list_head const		*old = head;

	for (i = old->next;; i = i->next) {
		assert(i != LIST_POISON0);
		assert(i != LIST_POISON1);

		assert(i == old->next);
		assert(i->prev == old);

		old = i;
		if (i == head)
			break;
	}
#else
	(void)head;
#endif
}

/*! \brief Returns whether list is empty
 *  \param[in] h list to be checked
 *  \return \c true iff list \a h is emtpy */
inline static bool	list_empty(struct list_head const * const h)
{
#ifdef DEBUG_LIST
	assert(h->prev != LIST_POISON0 && h->prev != LIST_POISON1);
	assert(h->next != LIST_POISON1 && h->next != LIST_POISON0);
	assert((h->next == h && h->prev == h) ||
	       (h->next != h && h->prev != h));
#endif

	return h->next == h;
}

inline static bool	list_singular(struct list_head const * const h)
{
#ifdef DEBUG_LIST
	assert(h->prev != LIST_POISON0 && h->prev != LIST_POISON1);
	assert(h->next != LIST_POISON1 && h->next != LIST_POISON0);
	assert((h->next == h && h->prev == h) ||
	       (h->next != h && h->prev != h));
#endif

	return h->next->next == h;
}

/*! \brief Initializes list datastructure
 *  \param[out] h list to be initialized */
inline static void	list_init(struct list_head *h)
{
	h->next = h;
	h->prev = h;
}

#define DECLARE_LIST(_list)	\
	{ .next = (_list), .prev = (_list) }

/*! \brief Adds a list head
 *  \param head  the list-head which shall be added after \a root
 *  \param root  list-head after which \a head shall be added
 */
inline static void	list_add(struct list_head *head,
				 struct list_head *root)
{
	struct list_head	*tmp = root->next;

#ifdef DEBUG_LIST
	assert(root->prev != LIST_POISON0 && root->prev != LIST_POISON1);
	assert(root->next != LIST_POISON1 && root->next != LIST_POISON0);

	assert((head->prev == LIST_POISON0 && head->next == LIST_POISON1) ||
	       list_empty(head));
#endif

	tmp->prev  = head;
	head->next = tmp;
	head->prev = root;
	root->next = head;

	list_validate(root);
}

/*! \brief Adds a list head before another one
 *  \param head  the list-head which shall be added before \a root
 *  \param root  list-head before which \a head shall be added
 */
inline static void	list_add_tail(struct list_head *head,
				      struct list_head *root)
{
#ifdef DEBUG_LIST
	assert(root->prev != LIST_POISON0 && root->prev != LIST_POISON1);
	assert(root->next != LIST_POISON1 && root->next != LIST_POISON0);
#endif

	list_add(head, root->prev);
	list_validate(root);
}

/*! \brief Removes a list head
 *  \param r list-head to be removed */
inline static void	list_del(struct list_head *r)
{
	struct list_head	*prev = r->prev;
	struct list_head	*next = r->next;

	prev->next = next;
	next->prev = prev;

	list_validate(prev);
	list_validate(next);

#ifdef DEBUG_LIST
	r->prev = LIST_POISON0;
	r->next = LIST_POISON1;
#endif
}

inline static void	list_del_init(struct list_head *r)
{
	list_del(r);
	list_init(r);
}

inline static void	list_move(struct list_head *head,
				  struct list_head *root)
{
	list_del(head);
	list_add(head, root);
}

inline static void	list_move_tail(struct list_head *head,
				       struct list_head *root)
{
	must_not_be_const(root);

	list_move(head, root->prev);
}

inline static void	list_splice(struct list_head *list,
				    struct list_head *root)
{
	if (!list_empty(list)) {
		struct list_head	*prev = list->prev;
		struct list_head	*next = list->next;

		next->prev = root;
		prev->next = root->next;

		root->next->prev = prev;
		root->next = next;

		list_init(list);
	}
}

inline static void	list_splice_tail(struct list_head *list,
					 struct list_head *root)
{
	list_splice(list, root->prev);
}

inline static bool	list_is_last(struct list_head const *head,
				     struct list_head const *root)
{
#ifdef DEBUG_LIST
	assert(root->prev != LIST_POISON0 && root->prev != LIST_POISON1);
	assert(root->next != LIST_POISON1 && root->next != LIST_POISON0);

	assert(head->prev != LIST_POISON0 && head->prev != LIST_POISON1);
	assert(head->next != LIST_POISON1 && head->next != LIST_POISON0);
#endif

	return head->next == root;
}

#define _list_assert_list_head(var)					\
	((var) +							\
	 BUILD_BUG_ON_ZERO(!__is_type(var, struct list_head *) &&	\
			   !__is_type(var, struct list_head const *)))

/*! \brief Returns object containing a list head
 *  \param HEAD pointer to a list-head
 *  \param STRUCT datastructure which contains \a HEAD
 *  \param ATTR attribute name of the \a HEAD list-head
 *  \return a pointer of type \a STRUCT * which points to the object
 *    containing \a HEAD */
#define list_entry(HEAD,STRUCT,ATTR)				\
	container_of(_list_assert_list_head(HEAD),STRUCT,ATTR)

#define list_first_entry(HEAD,STRUCT,ATTR)				\
	list_entry(_list_assert_list_head(HEAD)->next,STRUCT,ATTR)

#define list_last_entry(HEAD,STRUCT,ATTR)				\
	list_entry(_list_assert_list_head(HEAD)->prev,STRUCT,ATTR)

#define list_foreach(_it,_head) \
	for (_it = (_head)->next; _it != (_head); _it = (_it)->next)

#define list_foreach_entry(_v,_head,_attr)				\
	for ((_v) = list_entry((_head)->next, typeof(*(_v)), _attr);	\
	     &(_v)->_attr != (_head);					\
	     (_v) = list_entry((_v)->_attr.next, typeof(*(_v)), _attr))

#define list_foreach_save(_it,_tmp,_head)				\
	for (_it = (_head)->next, _tmp = (_it)->next;			\
	     _it != (_head); _it = (_tmp), _tmp = (_it)->next)

#define list_foreach_entry_save(_v,_tmp,_head,_attr)			\
	for ((_v) = list_entry((_head)->next, typeof(*(_v)), _attr),	\
		     (_tmp) = list_entry((_v)->_attr.next,		\
					 typeof(*(_v)), _attr);		\
	     &(_v)->_attr != (_head);					\
	     (_v) = (_tmp), (_tmp) = list_entry((_v)->_attr.next,	\
						typeof(*(_v)), _attr))
/*@}*/

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif	/* H_ENSC_LIB_LIST_H */
