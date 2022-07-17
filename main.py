# coding=utf-8
import crawl
from models import Threat
from environs import Env
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert


def on_conflict_do_update(sess, item):
    threat = Threat(ip=item.ip, threat_id_info=item.threat_id_info, domain_count=item.domain_count,
                    tag_count=item.tag_count, itel_count=item.itel_count, judge=item.judge, poc=item.poc,
                    ctime=item.ctime, source=item.source)
    insert_stmt = insert(Threat).values(
        ip=threat.ip,
        threat_id_info=threat.threat_id_info,
        domain_count=threat.domain_count,
        tag_count=threat.tag_count,
        itel_count=threat.itel_count,
        judge=threat.judge,
        poc=threat.poc,
        ctime=threat.ctime,
        source=threat.source
    )

    do_update_stmt = insert_stmt.on_conflict_do_update(
        index_elements=['ip'],
        set_=dict(
            threat_id_info=threat.threat_id_info,
            domain_count=threat.domain_count,
            tag_count=threat.tag_count,
            itel_count=threat.itel_count,
            judge=threat.judge,
            poc=threat.poc,
            ctime=threat.ctime,
            source=threat.source))
    sess.execute(do_update_stmt)

    sess.commit()


if __name__ == '__main__':
    env = Env()
    env.read_env()
    deploy_mode = env.str('DEPLOY_MODE', 'development')
    if deploy_mode == 'development':
        database_url = env.str('DEV_DATABASE_URL', 'development')
    elif deploy_mode == 'production':
        database_url = env.str('PROD_DATABASE_URL', 'development')
    else:
        database_url = env.str('DEV_DATABASE_URL', 'development')
        print('Warning: Environment variable DEPLOY_MODE is not set./r/n Using development mode by default')
    if not len(database_url) == 0:
        engine = create_engine(database_url)
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
    else:
        print('Error: Environment variable DATABASE_URL is not set./r/n Please set it and run again')
        exit(1)
    item_list = []
    feed_start_from = env.int('FEED_START_FROM', 1)
    feed_per_crawl = env.int('FEED_PER_CRAWL', 50)
    crawl.get_post_by_page(item_list, feed_start_from, feed_per_crawl)
    for item in item_list:
        print(item)
        on_conflict_do_update(session, item)
