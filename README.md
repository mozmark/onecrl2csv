# onecrl2csv
A thing to make CSV files containing human readible entries

## Building
You need to have [Go](https://golang.org) intalled.

CD to a directory containing onecrl2csv.go and do this:
```
go build onecrl2csv
```

## Running
Open a terminal window.

From the directory containing the binary, do this:
```
./onecrl2csv > filename.csv
```
### options
You can specify to location of the blocklist records like so:
```
./onecrl2csv -url=http://localhost:8080/v1/buckets/blocklists/collections/certificates/records
```

