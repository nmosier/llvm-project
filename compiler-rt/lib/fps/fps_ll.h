#include "fps/fps_util.h"

namespace __fps {

template <typename T>
class ForwardList {
  struct Node {
    T value;
    Node *next;

    Node(const T& value, Node *next): value(value), next(next) {}
    Node(T &&value, Node *next): value(static_cast<T &&>(value)), next(next) {}
  };
  
  Node *head;

public:
  ForwardList(): head(nullptr) {}

  ~ForwardList() {
    for (Node *it = head; it; ) {
      Node *cur = it;
      it = it->next;
      cur->~Node();
      free(cur);
    }
  }

  bool empty() const {
    return head == nullptr;
  }
  
  void push_front(const T &value) {
    void *mem = malloc(sizeof(Node));
    head = new (mem) Node(value, head);
  }

  class iterator {
    Node *node;
    friend class ForwardList<T>;
  public:
    T &operator*() {
      return node->value;
    }

    const T &operator*() const {
      return node->value;
    }

    T *operator->() {
      return &node->value;
    }

    const T *operator->() const {
      return &node->value;
    }

    iterator &operator++() {
      FPS_CHECK(node);
      node = node->next;
    }

    bool operator==(const iterator &o) const {
      return node == o.node;
    }

    bool operator!=(const iterator &o) const {
      return !(*this == o);
    }
  };

  iterator begin() {
    iterator it;
    it.node = head;
    return it;
  }

  iterator end() {
    iterator it;
    it.node = nullptr;
    return it;
  }
};

}
