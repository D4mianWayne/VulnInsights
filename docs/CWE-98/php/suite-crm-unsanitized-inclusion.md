


# Overview

This vulnerability was reported by [navsec](https://huntr.com/users/navsec)

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/22a27be9-f016-4daf-9887-c77eb3e1dc74/

[How to Identify Similar vulnerabilities](#how-to-identify-similar-vulnerabilities)

### Restricted LFI 

The application sends a request to the vulnerable endpoint i.e. `SubpanelCreates.php` file which, the application access the `Notes` modules that will be used by referencing them in the URL with `target_module` paramter, as seen in the file the way the `target_module` parameter is being handled is that it checks if the specified path has a file named `EditView.php` and `QuickCreate.php` file, if it is present it will include the file.

```php
if (file_exists('modules/'. $_REQUEST['target_module'] . '/EditView.php')) {
    $tpl = $_REQUEST['tpl'];
    if (is_file('modules/' . $target_module . '/' . $target_module . 'QuickCreate.php')) { // if there is a quickcreate override
        require_once('modules/' . $target_module . '/' . $target_module . 'QuickCreate.php');
        $editviewClass     = $target_module . 'QuickCreate'; // eg. OpportunitiesQuickCreate
        $editview          = new $editviewClass($target_module, 'modules/' . $target_module . '/tpls/' . $tpl);
        $editview->viaAJAX = true;
```
[SubpanelCreates.php](https://github.com/salesagility/SuiteCRM/blob/f30a84c603ecaffb24ce3a49a47c6cf5eb32ceb2/modules/Home/SubpanelCreates.php)

The vulnerability arises due to an attacker's ability to control the value of `target_module`, consider if we provide `/dev/shm` as the value for this parameter, it will be looking for `EditView.php` and `QuickCreate.php` file in `/dev/shm` folder.

> This could be leveraged in a scenario where an attacker possess ability to write files to the target system and using the described vulnerability to access the file, since the use `require_once` will include the PHP file in application context resulting in RCE.

### Patch

A [fix](https://github.com/salesagility/SuiteCRM/blob/54bc56c3bd9f1db75408db1c1d7d652c3f5f71e9/modules/Home/SubpanelCreates.php) was made to the `SuiteCRM`, a whitelist/blacklist mechanism by checking the value, a regex was implemented to check no directory traversal is possible.


```php
if (empty($target_module) || !isAllowedModuleName($target_module)) {
    throw new InvalidArgumentException('Invalid target_module');
}
```

```php
function isAllowedModuleName(string $value): bool {
    if (empty($value)) {
        return false;
    }

    $result = preg_match("/^[\w\-\_\.]+$/", $value);

    if (!empty($result)) {
        return true;
    }

    return false;
}
```

### How to Identify Similar vulnerabilities

The best way to identify vulnerabilities like this is to narrow down use of functions such as `require_once`, `include` or any similar function which includes a local PHP file from the system to the application's context. It is better to map out sources of input if any these functions are being called in a huge codebase, narrowing down the sources will help in betetr coverage.