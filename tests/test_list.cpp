#include <gtest/gtest.h>

extern "C" {
#include "sukat_list.h"
}

class sukatListTest : public ::testing::Test
{
protected:
  struct list_data
    {
      sukat_list_link_t link;
      int value;
    };
};

TEST_F(sukatListTest, testList)
{
  sukat_list_t list = { };
  sukat_list_link_t *iter;
  unsigned int i;
  const unsigned int n_entries = 128;
  const unsigned int removed_entry = 54;
  struct list_data entries[n_entries] = { };

  // Add all entries to list.
  for (i = 0; i < n_entries; i++)
    {
      entries[i].value = i;
      sukat_list_add_to_tail(&list, &entries[i].link);
    }

  // Iterate and check.
  i = 0;
  for (iter = sukat_list_begin(&list); iter; iter = sukat_list_next(iter))
    {
      struct list_data *data = sukat_list_data(iter, struct list_data, link);

      EXPECT_EQ(data->value, i);
      i++;
    }

  // Remove from middle.
  EXPECT_EQ(removed_entry, entries[removed_entry].value);
  sukat_list_remove(&list, &entries[removed_entry].link);
  for (iter = sukat_list_begin(&list); iter; iter = sukat_list_next(iter))
    {
      struct list_data *data = sukat_list_data(iter, struct list_data, link);

      EXPECT_NE(data->value, removed_entry);
    }

  // Remove from beginning.
  iter = sukat_list_begin(&list);
  sukat_list_remove(&list, iter);
  for (iter = sukat_list_begin(&list); iter; iter = sukat_list_next(iter))
    {
      struct list_data *data = sukat_list_data(iter, struct list_data, link);

      EXPECT_NE(data->value, 0);
    }

  // Remove from end.
  sukat_list_remove(&list, &entries[n_entries - 1].link);
  for (iter = sukat_list_begin(&list); iter; iter = sukat_list_next(iter))
    {
      struct list_data *data = sukat_list_data(iter, struct list_data, link);

      EXPECT_NE(data->value, n_entries - 1);
    }

  // Remove all.
  while ((iter = sukat_list_begin(&list)))
    {
      sukat_list_remove(&list, iter);
    }
}
