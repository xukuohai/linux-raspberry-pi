#! /bin/bash

Dir=$1
List=$2

pushd $Dir
rm -rf modnames
find . -name "*.ko" -type f > modnames
# Look through all of the modules, and throw any that have a dependency in
# our list into the list as well.
rm -rf dep.list dep2.list
rm -rf req.list req2.list
touch dep.list req.list
cp $2 .

for dep in `cat modnames`
do
  depends=`modinfo $dep | grep depends| cut -f2 -d":" | sed -e 's/^[ \t]*//'`
  [ -z "$depends" ] && continue;
  for mod in `echo $depends | sed -e 's/,/ /g'`
  do
    match=`grep "^$mod.ko" mod-extra.list` ||:
    if [ -z "$match" ]
    then
      continue
    else
      # check if the module we're looking at is in mod-extra too.  if so
      # we don't need to mark the dep as required
      mod2=`basename $dep`
      match2=`grep "^$mod2" mod-extra.list` ||:
      if [ -n "$match2" ]
      then
        continue
          #echo $mod2 >> notreq.list
        else
          echo $mod.ko >> req.list
      fi
    fi
  done
done

sort -u req.list > req2.list
sort -u mod-extra.list > mod-extra2.list
join -v 1 mod-extra2.list req2.list > mod-extra3.list

for mod in `cat mod-extra3.list`
do
  # get the path for the module
  modpath=`grep /$mod modnames` ||:
  [ -z "$modpath" ]  && continue;
  echo $modpath >> dep.list
done

sort -u dep.list > dep2.list

# now move the modules into the extra/ directory
for mod in `cat dep2.list`
do
  newpath=`dirname $mod | sed -e 's/kernel\//extra\//'`
  mkdir -p $newpath
  mv $mod $newpath
done

popd

# Remove modules from modules.order that we've moved into extra/, otherwise
# if we later call the modules_sign target it will fail trying to sign them
# because they no longer exist at the listed location.
sed -e 's/\.\/kernel\///g' ${Dir}/dep2.list > module-filter.list
grep -vF -f module-filter.list modules.order > modules.order.filtered
mv modules.order.filtered modules.order
rm module-filter.list

pushd $Dir
rm modnames dep.list dep2.list req.list req2.list
rm mod-extra.list mod-extra2.list mod-extra3.list
popd
