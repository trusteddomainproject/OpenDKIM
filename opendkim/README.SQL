OPENDKIM SQL NOTES
==================


Contributed by Todd Lyons


The OpenDKIM filter ("opendkim") supports numerous types of databases
for storing configuration information.  See the opendkim(8) man page for
a summary of the possibilities.

Certain data sets are expected to return multiple values in response to a
single query.  The KeyTable is a common example of this.  Configuring these
for SQL or LDAP backends can be tricky.  This document explains them in some
detail and provides a few example configurations.

The SigningTable lookup will use a signing pattern based on the message sender
to perform a lookup and must return an arbitrary "label", which can be any
string or number you wish to use.

The KeyTable lookup will use this label to search for and return the
following three pieces of data, in this order:

  domain name, selector, private key (in ASCII armor, or a filename)

In the simplest configuration, where you want to sign all emails for a
domain, all data can exist in the same table.  For this simplest
configuration example, assume that a table called "dkim" has these fields:

  `id` int(10) unsigned NOT NULL auto_increment,
  `domain_name` varchar(255) NOT NULL,
  `selector` varchar(63) NOT NULL,
  `private_key` text,
  `public_key` text,
  INDEX(domain_name)

A sample opendkim configuration that references a MySQL database could look
like this:

  SigningTable dsn:mysql://USER:PASSWORD@SERVER/DBNAME/table=dkim?keycol=domain_name?datacol=id
  KeyTable     dsn:mysql://USER:PASSWORD@SERVER/DBNAME/table=dkim?keycol=id?datacol=domain_name,selector,private_key

The strings USER, PASSWORD, SERVER and DBNAME would be replaced by the name
of the database user to be used, that user's database password, the hostname
where the server can be contacted, and the name of the database at that server
to be used, respectively.

The above data sets would then map to the following SQL queries:

  SELECT id FROM dkim WHERE domain_name='the_signing_pattern';
  SELECT domain_name,selector,private_key FROM dkim WHERE id='previous_answer';

In the first query, the answer returned (the "arbitrary label") is the ID of
the record that matches the signing pattern.  Since the intent is to sign all
records for that domain, the domain name is what queried.  The ID is
used to then lookup the domain name to sign with, the selector, and the
private key.

For example, a message from "user@example.com" with the above setup would
cause the following SigningTable queries:

  SELECT id FROM dkim WHERE domain_name='user@example.com';
  SELECT id FROM dkim WHERE domain_name='example.com';
  SELECT id FROM dkim WHERE domain_name='user@.com';
  SELECT id FROM dkim WHERE domain_name='.com';
  SELECT id FROM dkim WHERE domain_name='user@*';
  SELECT id FROM dkim WHERE domain_name='*';

If there is no match to any of these, then the SigningTable will not result
in a signature being added to the message.

Suppose one of these returns a value of 1293 for 'id'.  This is then fed to
a query to the KeyTable data set, resulting in the following query:

  SELECT domain_name,selector,private_key FROM dkim WHERE id='1293';

The content of those three fields are then used to construct the signature
on the message.

In a medium complicated setup, such as one where you potentially want to
specify different keys based on email address or subdomain name, this is best
implemented with two tables.  First, the "dkim" table above, then a second
table which will tie distinct labels to the domain/selector/key tuple.  As an
example, this second table, named 'dkim_signing', might have these fields:

  `id` int(10) unsigned NOT NULL auto_increment,
  `author` varchar(255) NOT NULL,
  `dkim_id` unsigned NOT NULL,
  INDEX(author)

The resulting opendkim configuration would be:

SigningTable dsn:mysql://USER:PASSWORD@SERVER/DB/table=dkim_signing?keycol=author?datacol=dkim_id
KeyTable     dsn:mysql://USER:PASSWORD@SERVER/DB/table=dkim?keycol=id?datacol=domain_name,selector,private_key

...which maps to the following SQL queries:

  SELECT dkim_id FROM dkim_signing WHERE author='the_signing_pattern';
  SELECT domain_name,selector,private_key FROM dkim WHERE id='previous_answer';

One other advantage of this medium complicated setup is that you could
define one key and have multiple authors in the signing table that point to
it (called a "Many-To-One" relationship).  In summary, this many-to-one
concept is the same as using flat files, but with the added advantage that
the data is stored in a central location that multiple mail servers can
access, and the signing and key configuration can be modified by changing the
SQL data without disturbing the filter itself in any way.
