# Overview

This vulnerability was reported by [lujiefsi](https://huntr.com/users/lujiefsi)

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/b7753929-b7bf-4072-9ff0-1ff62baba278/

[How to Identify Similar vulnerabilities](#how-to-identify-similar-vulnerabilities)

# Path Traversal in AttachmentService.java

The problem with the following code is that `belongId` is something which is user-controlled input and since it is being concatenated to the path which is later used for saving the uploaded file. Now, since we control the `belongId` we can just give `../` characters to traverse through the system.

```java
    public FileAttachmentMetadata saveAttachment(MultipartFile file, String attachmentType, String belongId) {
        String uploadPath = FileUtils.ATTACHMENT_DIR + "/" + attachmentType + "/" + belongId;
        FileUtils.uploadFile(file, uploadPath);
        final FileAttachmentMetadata fileAttachmentMetadata = new FileAttachmentMetadata();
        fileAttachmentMetadata.setId(UUID.randomUUID().toString());
        fileAttachmentMetadata.setName(file.getOriginalFilename());
        fileAttachmentMetadata.setType(getFileTypeWithoutEnum(fileAttachmentMetadata.getName()));
        fileAttachmentMetadata.setSize(file.getSize());
        fileAttachmentMetadata.setCreateTime(System.currentTimeMillis());
        fileAttachmentMetadata.setUpdateTime(System.currentTimeMillis());
        fileAttachmentMetadata.setCreator(SessionUtils.getUser().getName());
        fileAttachmentMetadata.setFilePath(uploadPath);
        fileAttachmentMetadataMapper.insert(fileAttachmentMetadata);
        return fileAttachmentMetadata;
    }
```


### Patch

The patch is rather simple but effective here as now there's a check for `/` character in the `belongId`, if there is an exception will be thrown.

```java
    public FileAttachmentMetadata saveAttachment(MultipartFile file, String attachmentType, String belongId) {
        if (attachmentType.contains("/") || belongId.contains("/")) {
            MSException.throwException(Translator.get("invalid_parameter"));
        }
        String uploadPath = FileUtils.ATTACHMENT_DIR + "/" + attachmentType + "/" + belongId;
        FileUtils.uploadFile(file, uploadPath);
        final FileAttachmentMetadata fileAttachmentMetadata = new FileAttachmentMetadata();
        fileAttachmentMetadata.setId(UUID.randomUUID().toString());
        fileAttachmentMetadata.setName(file.getOriginalFilename());
        fileAttachmentMetadata.setType(getFileTypeWithoutEnum(fileAttachmentMetadata.getName()));
        fileAttachmentMetadata.setSize(file.getSize());
        fileAttachmentMetadata.setCreateTime(System.currentTimeMillis());
        fileAttachmentMetadata.setUpdateTime(System.currentTimeMillis());
        fileAttachmentMetadata.setCreator(SessionUtils.getUser().getName());
        fileAttachmentMetadata.setFilePath(uploadPath);
        fileAttachmentMetadataMapper.insert(fileAttachmentMetadata);
        return fileAttachmentMetadata;
    }
```



---

### How to Identify Similar vulnerabilities

It is very important to look into the functions which handles file based operations and if the user-controlled data is being processed in any way which can affect the path of the files.