---
layout: page
title: Writeups
permalink: /writeups/
---

Technical writeups on hypervisors, reverse engineering, and low-level Windows internals.

{% for post in site.posts %}
### [{{ post.title }}]({{ post.url | relative_url }})
<small>{{ post.date | date: "%B %d, %Y" }}</small>
{% if post.tags %}
<small>{% for tag in post.tags %}`{{ tag }}`{% unless forloop.last %} {% endunless %}{% endfor %}</small>
{% endif %}

---
{% endfor %}
