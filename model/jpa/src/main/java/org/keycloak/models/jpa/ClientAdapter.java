package org.keycloak.models.jpa;

import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.IdentityProviderEntity;
import org.keycloak.models.jpa.entities.ProtocolMapperEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.ScopeMappingEntity;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class ClientAdapter implements ClientModel {
    protected ClientEntity entity;
    protected RealmModel realm;
    protected EntityManager em;

    public ClientAdapter(RealmModel realm, ClientEntity entity, EntityManager em) {
        this.realm = realm;
        this.entity = entity;
        this.em = em;
    }

    public ClientEntity getEntity() {
        return entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public String getClientId() {
        return entity.getName();
    }

    @Override
    public boolean isEnabled() {
        return entity.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        entity.setEnabled(enabled);
    }

    @Override
    public long getAllowedClaimsMask() {
        return entity.getAllowedClaimsMask();
    }

    @Override
    public void setAllowedClaimsMask(long mask) {
        entity.setAllowedClaimsMask(mask);
    }

    @Override
    public boolean isPublicClient() {
        return entity.isPublicClient();
    }

    @Override
    public void setPublicClient(boolean flag) {
        entity.setPublicClient(flag);
    }

    @Override
    public boolean isFrontchannelLogout() {
        return entity.isFrontchannelLogout();
    }

    @Override
    public void setFrontchannelLogout(boolean flag) {
        entity.setFrontchannelLogout(flag);
    }

    @Override
    public boolean isFullScopeAllowed() {
        return entity.isFullScopeAllowed();
    }

    @Override
    public void setFullScopeAllowed(boolean value) {
        entity.setFullScopeAllowed(value);
    }

    @Override
    public Set<String> getWebOrigins() {
        Set<String> result = new HashSet<String>();
        result.addAll(entity.getWebOrigins());
        return result;
    }



    @Override
    public void setWebOrigins(Set<String> webOrigins) {
        entity.setWebOrigins(webOrigins);
    }

    @Override
    public void addWebOrigin(String webOrigin) {
        entity.getWebOrigins().add(webOrigin);
    }

    @Override
    public void removeWebOrigin(String webOrigin) {
        entity.getWebOrigins().remove(webOrigin);
    }

    @Override
    public Set<String> getRedirectUris() {
        Set<String> result = new HashSet<String>();
        result.addAll(entity.getRedirectUris());
        return result;
    }

    @Override
    public void setRedirectUris(Set<String> redirectUris) {
        entity.setRedirectUris(redirectUris);
    }

    @Override
    public void addRedirectUri(String redirectUri) {
        entity.getRedirectUris().add(redirectUri);
    }

    @Override
    public void removeRedirectUri(String redirectUri) {
        entity.getRedirectUris().remove(redirectUri);
    }

    @Override
    public String getSecret() {
        return entity.getSecret();
    }

    @Override
    public void setSecret(String secret) {
        entity.setSecret(secret);
    }

    @Override
    public boolean validateSecret(String secret) {
        return secret.equals(entity.getSecret());
    }

    @Override
    public int getNotBefore() {
        return entity.getNotBefore();
    }

    @Override
    public void setNotBefore(int notBefore) {
        entity.setNotBefore(notBefore);
    }

    @Override
    public Set<RoleModel> getRealmScopeMappings() {
        Set<RoleModel> roleMappings = getScopeMappings();

        Set<RoleModel> appRoles = new HashSet<RoleModel>();
        for (RoleModel role : roleMappings) {
            RoleContainerModel container = role.getContainer();
            if (container instanceof RealmModel) {
                if (((RealmModel) container).getId().equals(realm.getId())) {
                    appRoles.add(role);
                }
            }
        }

        return appRoles;
    }



    @Override
    public Set<RoleModel> getScopeMappings() {
        TypedQuery<String> query = em.createNamedQuery("clientScopeMappingIds", String.class);
        query.setParameter("client", getEntity());
        List<String> ids = query.getResultList();
        Set<RoleModel> roles = new HashSet<RoleModel>();
        for (String roleId : ids) {
            RoleModel role = realm.getRoleById(roleId);
            if (role == null) continue;
            roles.add(role);
        }
        return roles;
    }

    @Override
    public void addScopeMapping(RoleModel role) {
        if (hasScope(role)) return;
        ScopeMappingEntity entity = new ScopeMappingEntity();
        entity.setClient(getEntity());
        RoleEntity roleEntity = RoleAdapter.toRoleEntity(role, em);
        entity.setRole(roleEntity);
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        TypedQuery<ScopeMappingEntity> query = getRealmScopeMappingQuery(role);
        List<ScopeMappingEntity> results = query.getResultList();
        if (results.size() == 0) return;
        for (ScopeMappingEntity entity : results) {
            em.remove(entity);
        }
    }

    protected TypedQuery<ScopeMappingEntity> getRealmScopeMappingQuery(RoleModel role) {
        TypedQuery<ScopeMappingEntity> query = em.createNamedQuery("hasScope", ScopeMappingEntity.class);
        query.setParameter("client", getEntity());
        RoleEntity roleEntity = RoleAdapter.toRoleEntity(role, em);
        query.setParameter("role", roleEntity);
        return query;
    }

    @Override
    public boolean hasScope(RoleModel role) {
        if (isFullScopeAllowed()) return true;
        Set<RoleModel> roles = getScopeMappings();
        if (roles.contains(role)) return true;

        for (RoleModel mapping : roles) {
            if (mapping.hasRole(role)) return true;
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!this.getClass().equals(o.getClass())) return false;

        ClientAdapter that = (ClientAdapter) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return entity.getId().hashCode();
    }

    @Override
    public String getProtocol() {
        return entity.getProtocol();
    }

    @Override
    public void setProtocol(String protocol) {
        entity.setProtocol(protocol);

    }

    @Override
    public void setAttribute(String name, String value) {
        entity.getAttributes().put(name, value);

    }

    @Override
    public void removeAttribute(String name) {
       entity.getAttributes().remove(name);
    }

    @Override
    public String getAttribute(String name) {
        return entity.getAttributes().get(name);
    }

    @Override
    public Map<String, String> getAttributes() {
        Map<String, String> copy = new HashMap<String, String>();
        copy.putAll(entity.getAttributes());
        return copy;
    }

    @Override
    public void updateAllowedIdentityProviders(List<String> identityProviders) {
        Collection<IdentityProviderEntity> entities = entity.getAllowedIdentityProviders();
        Set<String> already = new HashSet<String>();
        List<IdentityProviderEntity> remove = new ArrayList<IdentityProviderEntity>();
        for (IdentityProviderEntity rel : entities) {
            if (!contains(rel.getId(), identityProviders.toArray(new String[identityProviders.size()]))) {
                remove.add(rel);
            } else {
                already.add(rel.getId());
            }
        }
        for (IdentityProviderEntity entity : remove) {
            entities.remove(entity);
        }
        em.flush();
        for (String providerId : identityProviders) {
            if (!already.contains(providerId)) {
                TypedQuery<IdentityProviderEntity> query = em.createNamedQuery("findIdentityProviderById", IdentityProviderEntity.class).setParameter("id", providerId);
                IdentityProviderEntity providerEntity = query.getSingleResult();
                entities.add(providerEntity);
            }
        }
        em.flush();
    }

    @Override
    public List<String> getAllowedIdentityProviders() {
        Collection<IdentityProviderEntity> entities = entity.getAllowedIdentityProviders();
        List<String> providers = new ArrayList<String>();

        for (IdentityProviderEntity entity : entities) {
            providers.add(entity.getId());
        }

        return providers;
    }

    @Override
    public boolean hasIdentityProvider(String providerId) {
        List<String> allowedIdentityProviders = getAllowedIdentityProviders();

        if (allowedIdentityProviders.isEmpty()) {
            return true;
        }

        return allowedIdentityProviders.contains(providerId);
    }

    public static boolean contains(String str, String[] array) {
        for (String s : array) {
            if (str.equals(s)) return true;
        }
        return false;
    }

    @Override
    public Set<ProtocolMapperModel> getProtocolMappers() {
        Set<ProtocolMapperModel> mappings = new HashSet<ProtocolMapperModel>();
        for (ProtocolMapperEntity entity : this.entity.getProtocolMappers()) {
            ProtocolMapperModel mapping = new ProtocolMapperModel();
            mapping.setId(entity.getId());
            mapping.setName(entity.getName());
            mapping.setProtocol(entity.getProtocol());
            mapping.setProtocolMapper(entity.getProtocolMapper());
            mapping.setAppliedByDefault(entity.isAppliedByDefault());
            mapping.setConsentRequired(entity.isConsentRequired());
            mapping.setConsentText(entity.getConsentText());
            Map<String, String> config = new HashMap<String, String>();
            if (entity.getConfig() != null) {
                config.putAll(entity.getConfig());
            }
            mapping.setConfig(config);
            mappings.add(mapping);
        }
        return mappings;
    }

    protected ProtocolMapperEntity findProtocolMapperByName(String protocol, String name) {
        TypedQuery<ProtocolMapperEntity> query = em.createNamedQuery("getProtocolMapperByNameProtocol", ProtocolMapperEntity.class);
        query.setParameter("name", name);
        query.setParameter("protocol", protocol);
        query.setParameter("realm", entity.getRealm());
        List<ProtocolMapperEntity> entities = query.getResultList();
        if (entities.size() == 0) return null;
        if (entities.size() > 1) throw new IllegalStateException("Should not be more than one protocol mapper with same name");
        return query.getResultList().get(0);

    }

    @Override
    public void addProtocolMappers(Set<String> mappings) {
        Collection<ProtocolMapperEntity> entities = entity.getProtocolMappers();
        Set<String> already = new HashSet<String>();
        for (ProtocolMapperEntity rel : entities) {
            already.add(rel.getId());
        }
        for (String id : mappings) {
            if (!already.contains(id)) {
                ProtocolMapperEntity mapping = em.find(ProtocolMapperEntity.class, id);
                if (mapping != null) {
                    entities.add(mapping);
                }
            }
        }
        em.flush();
    }

    @Override
    public void removeProtocolMappers(Set<String> mappings) {
        Collection<ProtocolMapperEntity> entities = entity.getProtocolMappers();
        List<ProtocolMapperEntity> remove = new LinkedList<ProtocolMapperEntity>();
        for (ProtocolMapperEntity rel : entities) {
            if (mappings.contains(rel.getId())) remove.add(rel);
        }
        for (ProtocolMapperEntity entity : remove) {
            entities.remove(entity);
        }
        em.flush();
    }
    @Override
    public void setProtocolMappers(Set<String> mappings) {
        Collection<ProtocolMapperEntity> entities = entity.getProtocolMappers();
        Iterator<ProtocolMapperEntity> it = entities.iterator();
        Set<String> already = new HashSet<String>();
        while (it.hasNext()) {
            ProtocolMapperEntity mapper = it.next();
            if (mappings.contains(mapper.getId())) {
                already.add(mapper.getId());
                continue;
            }
            it.remove();
        }
        for (String id : mappings) {
            if (!already.contains(id)) {
                ProtocolMapperEntity mapping = em.find(ProtocolMapperEntity.class, id);
                if (mapping != null) {
                    entities.add(mapping);
                }
            }
        }
        em.flush();
    }


}
