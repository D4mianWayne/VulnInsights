# Overview

This vulnerability was reported by [harpsiford](https://huntr.com/users/harpsiford)

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/604b0ff1-860a-4027-82ef-d12a187233e9/

[How to Identify Similar vulnerabilities](#how-to-identify-similar-vulnerabilities)

> This is something which is used by many people, from a security prespective you want a token which serves as an integrity of an action to be random and not guessable. Often time, programmatically there exists multiple classes that can generate random numbers or string. Problem with functions/methods like this is that they are not [truly random]() and hence does not provide a good entropy for generating the tokens. In order to tackle this, many new implementations of PRNG algorithms has been done where they make use of `seed` specified by the developer to generate random numbers.

### Use of `RandomStringUtils` Package for Generating Tokens

In the `alovoa` application relies on `RandomStringUtils.randomAlphaNumeric` to generate a token for performing user account based operations such as registration, deletion and password reset.

```java

    public UserDeleteToken deleteAccountRequest() throws MessagingException, IOException, AlovoaException {
        User user = authService.getCurrentUser(true);
        UserDeleteToken token = new UserDeleteToken();
        Date currentDate = new Date();

        token.setContent(RandomStringUtils.randomAlphanumeric(tokenLength));
        token.setDate(currentDate);
        token.setUser(user);
        user.setDeleteToken(token);
        user = userRepo.saveAndFlush(user);

        mailService.sendAccountDeleteRequest(user);

        return user.getDeleteToken();
    }

```
(User Delete Action)[https://github.com/Alovoa/alovoa/blob/ace5c183a790b45a00cc437f563a8a34a5599783/src/main/java/com/nonononoki/alovoa/service/UserService.java]

Same logic exists for generating password reset tokens as well:

```java
[..snip..]
		//user has social login, do not assign new password!
		if (u.getPassword() != null) {
			UserPasswordToken token = new UserPasswordToken();
			token.setContent(RandomStringUtils.randomAlphanumeric(tokenLength));
			token.setDate(new Date());
			token.setUser(u);
			u.setPasswordToken(token);
			u = userRepo.saveAndFlush(u);
	
			mailService.sendPasswordResetMail(u);
			
			SecurityContextHolder.clearContext();
	
			return u.getPasswordToken();
		} else {
			throw new AlovoaException("user_has_social_login");
		}
```
[PasswordService.java](https://github.com/Alovoa/alovoa/blob/ace5c183a790b45a00cc437f563a8a34a5599783/src/main/java/com/nonononoki/alovoa/service/PasswordService.java)


There is a [public POC](https://github.com/alex91ar/randomstringutils) which takes a deep dive into the implementation of `RandomStringUtils.randomAlphanumeric` and reverse engineer the algorithm to predict past and future genrated numbers.

### Patch

---

### How to Identify Similar vulnerabilities

It is very important to look into the functions that has been obsolete and possess considerable security concerns such as the one we discussed.