/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationConsentServiceConfig {

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource,
			TenantPerIssuerComponentRegistry componentRegistry,
			RegisteredClientRepository registeredClientRepository) {

		componentRegistry.register("issuer1", OAuth2AuthorizationConsentService.class,
				new JdbcOAuth2AuthorizationConsentService(
						new JdbcTemplate(issuer1DataSource), registeredClientRepository));
		componentRegistry.register("issuer2", OAuth2AuthorizationConsentService.class,
				new JdbcOAuth2AuthorizationConsentService(
						new JdbcTemplate(issuer2DataSource), registeredClientRepository));

		return new DelegatingOAuth2AuthorizationConsentService(componentRegistry);
	}

	private static class DelegatingOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

		private final TenantPerIssuerComponentRegistry componentRegistry;

		private DelegatingOAuth2AuthorizationConsentService(TenantPerIssuerComponentRegistry componentRegistry) {
			this.componentRegistry = componentRegistry;
		}

		@Override
		public void save(OAuth2AuthorizationConsent authorizationConsent) {
			getAuthorizationConsentService().save(authorizationConsent);
		}

		@Override
		public void remove(OAuth2AuthorizationConsent authorizationConsent) {
			getAuthorizationConsentService().remove(authorizationConsent);
		}

		@Override
		public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
			return getAuthorizationConsentService().findById(registeredClientId, principalName);
		}

		private OAuth2AuthorizationConsentService getAuthorizationConsentService() {
			OAuth2AuthorizationConsentService authorizationConsentService =
					this.componentRegistry.get(OAuth2AuthorizationConsentService.class);
			Assert.state(authorizationConsentService != null,
					"OAuth2AuthorizationConsentService not found for \"requested\" issuer identifier.");
			return authorizationConsentService;
		}

	}

}
